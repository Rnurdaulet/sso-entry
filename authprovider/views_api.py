import secrets
import logging
from datetime import datetime, timedelta
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakAuthenticationError

from .keycloak.users import create_or_get_user
from .keycloak.client import get_keycloak_admin
from .ebdp.orleu import fetch_user_from_orleu
from authprovider.nca import verify_ecp_signature
from authprovider.utils.auth_code_store import save_auth_code
from authprovider.utils.client_check import is_valid_client

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

            code = f"code-{secrets.token_urlsafe(24)}"
            save_auth_code(code, {
                "sub": iin,
                "name": name,
                "client_id": client_id,
                "nonce": nonce,
                "exp": datetime.utcnow() + timedelta(minutes=5)
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
                "exp": datetime.utcnow() + timedelta(minutes=5)
            })

            params = urlencode({"code": code, "state": state})
            return JsonResponse({"redirect_url": f"{redirect_uri}?{params}"}, status=200)

        except KeycloakAuthenticationError as e:
            logger.warning(f"[password_login] Неверный логин или пароль: {username}")
            return Response({"error": "invalid_credentials", "detail": str(e)}, status=403)
        except Exception as e:
            logger.exception("[password_login] Внутренняя ошибка")
            return Response({"error": "server_error", "detail": str(e)}, status=500)


class ChangePasswordView(APIView):
    def post(self, request):
        client_id = request.data.get("client_id")
        if not is_valid_client(client_id, None):
            return Response({"error": "invalid_client"}, status=401)

        username = request.data.get("username")
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not all([username, current_password, new_password]):
            return Response({"error": "missing_parameters"}, status=400)

        try:
            # Step 1: Проверка текущего пароля
            token_resp = requests.post(
                f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": settings.KEYCLOAK_CLIENT_ID,
                    "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
                    "username": username,
                    "password": current_password
                },
                timeout=5
            )
            token_resp.raise_for_status()
            logger.info(f"[password_change] Текущий пароль подтверждён: {username}")
        except requests.RequestException:
            return Response({"error": "invalid_credentials"}, status=403)

        try:
            # Step 2: Смена пароля
            kc = get_keycloak_admin()
            users = kc.get_users(query={"username": username})
            if not users:
                return Response({"error": "user_not_found"}, status=404)

            kc.set_user_password(users[0]["id"], new_password, temporary=False)
            logger.info(f"[password_change] Пароль успешно обновлён: {username}")
            return Response({"status": "password_changed"})
        except Exception as e:
            logger.exception("[password_change] Ошибка при смене пароля")
            return Response({"error": "admin_error", "detail": str(e)}, status=500)
