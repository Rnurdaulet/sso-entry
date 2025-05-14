import requests
from keycloak import KeycloakOpenID, KeycloakAuthenticationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .nca import verify_ecp_signature
from .keycloak import create_or_get_user, sign_id_token, is_valid_client

from django.http import HttpResponseRedirect, JsonResponse
from urllib.parse import urlencode
import secrets
from datetime import datetime, timedelta
from .auth_code_store import save_auth_code


class ECPLoginView(APIView):
    def post(self, request):
        signed_data = request.data.get("signed_data")
        nonce = request.data.get("nonce")
        client_id = request.data.get("client_id")
        redirect_uri = request.data.get("redirect_uri")
        state = request.data.get("state")

        if not all([signed_data, nonce, client_id, redirect_uri, state]):
            return Response({"error": "missing_parameters"}, status=400)

        try:
            iin, name = verify_ecp_signature(signed_data, nonce)
            create_or_get_user(iin, name)

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
            return Response({"error": "missing_parameters"}, status=400)

        keycloak_openid = KeycloakOpenID(
            server_url=f"{settings.KEYCLOAK_URL}/",
            realm_name=settings.KEYCLOAK_REALM,
            client_id=settings.KEYCLOAK_CLIENT_ID,
            client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
        )

        try:
            token = keycloak_openid.token(username, password)
            # Можно также получить userinfo при необходимости:
            # userinfo = keycloak_openid.userinfo(token["access_token"])

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
            return Response({"error": "invalid_credentials", "detail": str(e)}, status=403)
        except Exception as e:
            return Response({"error": "server_error", "detail": str(e)}, status=500)


class ChangePasswordView(APIView):
    def post(self, request):
        if not is_valid_client(request):
            return Response({"error": "invalid_client"}, status=status.HTTP_401_UNAUTHORIZED)

        username = request.data.get("username")
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")
        client_id = request.data.get("client_id")

        # Step 1: Login and get access token
        token_url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
        try:
            login_resp = requests.post(token_url, data={
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
                "username": username,
                "password": current_password
            })
            login_resp.raise_for_status()
            token_data = login_resp.json()
            access_token = token_data.get("access_token")
        except requests.HTTPError:
            return Response({"error": "invalid_credentials"}, status=status.HTTP_403_FORBIDDEN)

        # Step 2: Change password via Keycloak Admin API
        try:
            admin_token = requests.post(
                f"{settings.KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "sso-proxy",
                    "client_secret": settings.KEYCLOAK_ADMIN_SECRET
                }
            ).json()["access_token"]

            headers = {"Authorization": f"Bearer {admin_token}"}
            users = requests.get(
                f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users?username={username}",
                headers=headers
            ).json()

            if not users:
                return Response({"error": "user_not_found"}, status=404)

            user_id = users[0]["id"]

            change_resp = requests.put(
                f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}/reset-password",
                headers={"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"},
                json={
                    "type": "password",
                    "value": new_password,
                    "temporary": False
                }
            )
            if change_resp.status_code == 204:
                return Response({"status": "password_changed"})
            else:
                return Response({"error": "change_failed"}, status=500)

        except Exception as e:
            return Response({"error": "admin_error", "detail": str(e)}, status=500)
