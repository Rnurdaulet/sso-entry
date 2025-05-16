import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from django.http import JsonResponse, HttpResponseRedirect
import jwt
from jwt import InvalidTokenError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from keycloak.exceptions import KeycloakAuthenticationError, KeycloakGetError

from .serializers import PasswordLoginSerializer, ECPLoginSerializer, SetPasswordSerializer, ForgotPasswordSerializer
from .keycloak.client import get_keycloak_openid, get_keycloak_admin
from .keycloak.users import create_or_get_user, check_password_exists
from .utils.client_check import is_valid_client, is_valid_redirect_uri
from .utils.jwt_utils import sign_id_token, verify_id_token
from authprovider.nca import verify_ecp_signature
from authprovider.utils.auth_code_store import save_auth_code

logger = logging.getLogger(__name__)

class LoginThrottle(UserRateThrottle):
    rate = '5/min'

def create_auth_code_response(sub: str, name: str, client_id: str, nonce: str, redirect_uri: str, state: str) -> JsonResponse:
    code = f"code-{secrets.token_urlsafe(24)}"
    payload = {
        "sub": sub,
        "name": name,
        "client_id": client_id,
        "nonce": nonce,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    save_auth_code(code, payload)
    logger.info(f"[auth_code] Код авторизации создан для {sub}")
    return JsonResponse({
        "redirect_url": f"{redirect_uri}?{urlencode({'code': code, 'state': state})}"
    }, status=200)

class ECPLoginView(APIView):
    throttle_classes = [LoginThrottle]

    def post(self, request):
        serializer = ECPLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            iin, name = verify_ecp_signature(data["signed_data"], data["nonce"])
            logger.info(f"[ecp_login] ЭЦП подтверждена: {iin} ({name})")

            user_id = create_or_get_user(iin, name)
            if not user_id:
                logger.error(f"[ecp_login] Ошибка создания пользователя: {iin}")
                return Response({"error": "user_creation_failed"}, status=500)

            if not check_password_exists(iin):
                id_token = sign_id_token(
                    sub=iin,
                    name=name,
                    aud=data["client_id"],
                    nonce=data["nonce"],
                    extra={"redirect_uri": data["redirect_uri"], "state": data["state"]},
                )
                logger.info(f"[ecp_login] Пароль отсутствует — редирект на /set-password для {iin}")
                return JsonResponse({"redirect_url": f"/set-password/?id_token={id_token}"}, status=200)

            return create_auth_code_response(
                sub=iin,
                name=name,
                client_id=data["client_id"],
                nonce=data["nonce"],
                redirect_uri=data["redirect_uri"],
                state=data["state"]
            )

        except Exception as e:
            logger.exception(f"[ecp_login] Ошибка авторизации через ЭЦП: {e}")
            return Response({"error": "invalid_signature", "detail": str(e)}, status=400)

class PasswordLoginView(APIView):
    throttle_classes = [LoginThrottle]

    def post(self, request):
        serializer = PasswordLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            keycloak_openid = get_keycloak_openid()
            token = keycloak_openid.token(data["username"], data["password"])
            logger.info(f"[password_login] Успешный вход: {data['username']}")

            return create_auth_code_response(
                sub=data["username"],
                name=data["username"],
                client_id=data["client_id"],
                nonce=data["nonce"],
                redirect_uri=data["redirect_uri"],
                state=data["state"]
            )

        except KeycloakAuthenticationError as e:
            logger.warning(f"[password_login] Неверные учётные данные: {data['username']}")
            return Response({"error": "invalid_credentials", "detail": str(e)}, status=403)

        except Exception as e:
            logger.exception(f"[password_login] Внутренняя ошибка при входе: {e}")
            return Response({"error": "server_error", "detail": str(e)}, status=500)

class SetPasswordView(APIView):
    def post(self, request):
        serializer = SetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            payload = verify_id_token(data["id_token"])
            client_id = payload.get("aud")
            redirect_uri = payload.get("redirect_uri")
            state = payload.get("state")
            nonce = payload.get("nonce")
            name = payload.get("name", data["username"])
            reset_password = payload.get("reset_password", False)

            if not all([client_id, redirect_uri, state]):
                return Response({"error": "invalid_token_payload"}, status=400)

        except InvalidTokenError as e:
            logger.warning(f"[set_password] Невалидный id_token: {e}")
            return Response({"error": "invalid_token"}, status=400)

        try:
            kc = get_keycloak_admin()
            users = kc.get_users(query={"username": data["username"]})
            if not users:
                return Response({"error": "user_not_found"}, status=404)

            user_id = users[0]["id"]
            credentials = kc.get_credentials(user_id)
            has_password = any(c["type"] == "password" for c in credentials)

            if has_password and not reset_password:
                return Response({"error": "password_already_exists"}, status=400)

            kc.set_user_password(user_id, data["new_password"], temporary=False)
            logger.info(f"[set_password] Пароль успешно установлен: {data['username']}")

            return create_auth_code_response(
                sub=data["username"],
                name=name,
                client_id=client_id,
                nonce=nonce,
                redirect_uri=redirect_uri,
                state=state
            )

        except KeycloakGetError as e:
            logger.warning(f"[set_password] Keycloak отказал: {e}")
            return Response({"error": "keycloak_error", "detail": str(e)}, status=502)

        except Exception as e:
            logger.exception("[set_password] Ошибка при установке пароля")
            return Response({"error": "admin_error", "detail": str(e)}, status=500)

class ForgotPasswordInitiateView(APIView):
    def post(self, request):
        signed_data = request.data.get("signed_data")
        nonce = request.data.get("nonce")
        client_id = request.data.get("client_id")
        redirect_uri = request.data.get("redirect_uri")
        state = request.data.get("state")

        if not all([signed_data, nonce, client_id, redirect_uri, state]):
            return Response({"error": "missing_parameters"}, status=400)

        # if not is_valid_client(client_id):
        #     return Response({"error": "invalid_client"}, status=403)
        #
        # if not is_valid_redirect_uri(client_id, redirect_uri):
        #     return Response({"error": "invalid_redirect_uri"}, status=403)

        try:
            iin, name = verify_ecp_signature(signed_data, nonce)
            kc = get_keycloak_admin()
            users = kc.get_users(query={"username": iin})
            if not users:
                return Response({"error": "user_not_found"}, status=404)

            user_id = users[0]["id"]
            credentials = kc.get_credentials(user_id)
            has_password = any(c["type"] == "password" for c in credentials)

            if not has_password:
                return Response({"error": "no_password"}, status=403)

            id_token = sign_id_token(
                sub=iin,
                name=name,
                aud=client_id,
                nonce=nonce,
                extra={
                    "redirect_uri": redirect_uri,
                    "state": state,
                    "reset_password": True
                }
            )

            encoded_url = "/forgot-password-form/?" + urlencode({
                "id_token": id_token
            })

            return Response({
                "id_token": id_token,
                "redirect_url": encoded_url
            })

        except Exception as e:
            logger.exception("[forgot_password/initiate] Ошибка")
            return Response({"error": "signature_verification_failed", "detail": str(e)}, status=400)


class ForgotPasswordCompleteView(APIView):
    def post(self, request):
        id_token = request.data.get("id_token")
        new_password = request.data.get("new_password")

        if not id_token or not new_password:
            return Response({"error": "missing_parameters"}, status=400)

        try:
            payload = verify_id_token(id_token)
            iin = payload.get("sub")
            client_id = payload.get("aud")
            nonce = payload.get("nonce")
            redirect_uri = payload.get("redirect_uri")
            state = payload.get("state")

            if not all([iin, client_id, redirect_uri, state]):
                return Response({"error": "invalid_token_payload"}, status=400)

            # if not is_valid_client(client_id) or not is_valid_redirect_uri(client_id, redirect_uri):
            #     return Response({"error": "invalid_client_or_redirect_uri"}, status=403)

            kc = get_keycloak_admin()
            users = kc.get_users(query={"username": iin})
            if not users:
                return Response({"error": "user_not_found"}, status=404)

            user_id = users[0]["id"]
            kc.set_user_password(user_id, new_password, temporary=False)
            logger.info(f"[forgot_password/complete] Пароль сброшен для {iin}")

            return JsonResponse({"status": "ok"})

        except Exception as e:
            logger.exception("[forgot_password/complete] Ошибка")
            return Response({"error": "server_error", "detail": str(e)}, status=500)
