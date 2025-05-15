import secrets
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import jwt
import requests
from django.conf import settings
from django.http import JsonResponse, HttpResponseRedirect
from jwt import decode as jwt_decode, InvalidTokenError
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError

from .keycloak.users import create_or_get_user, check_password_exists
from .keycloak.client import get_keycloak_admin
from .ebdp.orleu import fetch_user_from_orleu
from authprovider.nca import verify_ecp_signature
from authprovider.utils.auth_code_store import save_auth_code
from authprovider.utils.client_check import is_valid_client
from .utils.jwt_utils import sign_id_token

logger = logging.getLogger(__name__)


class ECPLoginView(APIView):
    def post(self, request):
        signed_data = request.data.get("signed_data")
        nonce = request.data.get("nonce")
        client_id = request.data.get("client_id")
        redirect_uri = request.data.get("redirect_uri")
        state = request.data.get("state")

        if not all([signed_data, nonce, client_id, redirect_uri, state]):
            logger.warning("[ecp_login] Отсутствуют параметры")
            return Response({"error": "missing_parameters"}, status=400)

        try:
            iin, name = verify_ecp_signature(signed_data, nonce)
            logger.info(f"[ecp_login] Подпись подтверждена: {iin} ({name})")

            user_id = create_or_get_user(iin, name)
            if not user_id:
                return Response({"error": "user_creation_failed"}, status=500)

            # ➕ Проверка: если пароля нет — редирект на set-password
            if not check_password_exists(iin):
                id_token = sign_id_token(
                    sub=iin,
                    name=name,
                    aud=client_id,
                    nonce=nonce,
                    extra={
                        "redirect_uri": redirect_uri,
                        "state": state
                    }
                )
                logger.info(f"[ecp_login] Пароль отсутствует — редирект на set-password для {iin}")
                return JsonResponse({
                    "redirect_url": f"/set-password/?id_token={id_token}"
                }, status=200)

            # Всё хорошо — выдаём код авторизации
            code = f"code-{secrets.token_urlsafe(24)}"
            save_auth_code(code, {
                "sub": iin,
                "name": name,
                "client_id": client_id,
                "nonce": nonce,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
            })

            params = urlencode({"code": code, "state": state})
            return JsonResponse({"redirect_url": f"{redirect_uri}?{params}"}, status=200)

        except Exception as e:
            logger.exception("[ecp_login] Ошибка при входе через ЭЦП")
            return Response({"error": "invalid_signature", "detail": str(e)}, status=400)

class PasswordLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        client_id = request.data.get("client_id")
        redirect_uri = request.data.get("redirect_uri")
        state = request.data.get("state")
        nonce = request.data.get("nonce")

        if not all([username, password, client_id, redirect_uri, state, nonce]):
            logger.warning("[password_login] Отсутствуют параметры")
            return Response({"error": "missing_parameters"}, status=400)

        try:
            keycloak_openid = KeycloakOpenID(
                server_url=f"{settings.KEYCLOAK_URL}/",
                realm_name=settings.KEYCLOAK_REALM,
                client_id=settings.KEYCLOAK_CLIENT_ID,
                client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
            )
            keycloak_openid.token(username, password)
            logger.info(f"[password_login] Вход успешен: {username}")

            code = f"code-{secrets.token_urlsafe(24)}"
            save_auth_code(code, {
                "sub": username,
                "name": username,
                "client_id": client_id,
                "nonce": nonce,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
            })

            params = urlencode({"code": code, "state": state})
            return JsonResponse({"redirect_url": f"{redirect_uri}?{params}"}, status=200)

        except KeycloakAuthenticationError as e:
            logger.warning(f"[password_login] Неверный логин или пароль: {username}")
            return Response({"error": "invalid_credentials", "detail": str(e)}, status=403)
        except Exception as e:
            logger.exception("[password_login] Внутренняя ошибка")
            return Response({"error": "server_error", "detail": str(e)}, status=500)

class SetPasswordView(APIView):
    def post(self, request):
        username = request.data.get("username")
        new_password = request.data.get("new_password")
        id_token = request.data.get("id_token")

        if not all([username, new_password, id_token]):
            return Response({"error": "missing_parameters"}, status=400)

        if len(new_password) < 6:
            return Response({"error": "password_too_short"}, status=400)

        try:
            payload = jwt_decode(id_token, options={"verify_signature": False})
            client_id = payload.get("aud")
            redirect_uri = payload.get("redirect_uri")
            state = payload.get("state")
            nonce = payload.get("nonce")
            name = payload.get("name", username)

            if not all([client_id, redirect_uri, state]):
                return Response({"error": "invalid_token_payload"}, status=400)

        except InvalidTokenError as e:
            logger.warning(f"[set_password] Невалидный id_token: {e}")
            return Response({"error": "invalid_token"}, status=400)

        # if not is_valid_client(client_id, settings.KEYCLOAK_CLIENT_SECRET):
        #     return Response({"error": "invalid_client"}, status=401)

        try:
            kc = get_keycloak_admin()
            users = kc.get_users(query={"username": username})
            if not users:
                return Response({"error": "user_not_found"}, status=404)

            user_id = users[0]["id"]

            # Проверка: уже есть пароль — нельзя установить второй
            credentials = kc.get_credentials(user_id)
            has_password = any(c["type"] == "password" for c in credentials)

            reset_password = payload.get("reset_password", False)

            if has_password and not reset_password:
                return Response({"error": "password_already_exists"}, status=400)

            kc.set_user_password(user_id, new_password, temporary=False)
            logger.info(f"[set_password] Пароль установлен: {username}")

            # 🎁 Генерируем auth_code и редиректим
            code = f"code-{secrets.token_urlsafe(24)}"
            save_auth_code(code, {
                "sub": username,
                "name": name,
                "client_id": client_id,
                "nonce": nonce,
                "exp": datetime.now(timezone.utc) + timedelta(minutes=5)
            })

            params = urlencode({"code": code, "state": state})
            return JsonResponse({
                "status": "password_set",
                "redirect_url": f"{redirect_uri}?{params}"
            })

        except Exception as e:
            logger.exception("[set_password] Ошибка установки пароля")
            return Response({"error": "admin_error", "detail": str(e)}, status=500)

class ForgotPasswordView(APIView):
    def post(self, request):
        signed_data = request.data.get("signed_data")
        id_token = request.data.get("id_token")
        new_password = request.data.get("new_password")

        if not signed_data or not id_token or not new_password:
            return Response({"error": "missing_parameters"}, status=400)

        try:
            payload = jwt.decode(id_token, options={"verify_signature": False})
            iin = payload["sub"]
            name = payload["name"]
            client_id = payload["aud"]
            nonce = payload.get("nonce")
            redirect_uri = payload.get("redirect_uri")
            state = payload.get("state")

        except Exception as e:
            logger.warning(f"[forgot_password] Неверный id_token: {e}")
            return Response({"error": "invalid_token"}, status=400)

        try:
            # Проверяем ЭЦП
            verified_iin, _ = verify_ecp_signature(signed_data, nonce)
            if verified_iin != iin:
                return Response({"error": "iin_mismatch"}, status=403)

            kc = get_keycloak_admin()
            users = kc.get_users(query={"username": iin})
            if not users:
                return Response({"error": "user_not_found"}, status=404)

            user_id = users[0]["id"]
            kc.set_user_password(user_id, new_password, temporary=False)
            logger.info(f"[forgot_password] Пароль сброшен: {iin}")

            # ⏎ Возврат на /login/
            query = urlencode({
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "nonce": nonce,
            })
            return HttpResponseRedirect(f"/login/?{query}")

        except Exception as e:
            logger.exception("[forgot_password] Ошибка при сбросе пароля")
            return Response({"error": "server_error", "detail": str(e)}, status=500)
