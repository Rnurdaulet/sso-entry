import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from .nca import verify_ecp_signature
from .keycloak import create_or_get_user, sign_id_token, is_valid_client


class ECPLoginView(APIView):
    def post(self, request):
        if not is_valid_client(request):
            return Response({"error": "invalid_client"}, status=status.HTTP_401_UNAUTHORIZED)

        signed_data = request.data.get("signed_data")
        nonce = request.data.get("nonce")
        client_id = request.data.get("client_id")

        if not signed_data or not nonce:
            return Response({"error": "missing_parameters"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            iin, name = verify_ecp_signature(signed_data, nonce)
            create_or_get_user(iin, name)
            id_token = sign_id_token(iin, name, aud=client_id)
            return Response({
                "access_token": f"access-token-{iin}",
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 3600
            })
        except Exception as e:
            return Response({"error": "invalid_signature", "error_description": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class PasswordLoginView(APIView):
    def post(self, request):
        if not is_valid_client(request):
            return Response({"error": "invalid_client"}, status=status.HTTP_401_UNAUTHORIZED)

        username = request.data.get("username")
        password = request.data.get("password")
        client_id = request.data.get("client_id")

        token_url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
        resp = None

        try:
            resp = requests.post(token_url, data={
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": settings.KEYCLOAK_CLIENT_SECRET,
                "username": username,
                "password": password
            })
            resp.raise_for_status()
            return Response(resp.json(), status=200)

        except requests.HTTPError as e:
            if resp is not None:
                try:
                    return Response(resp.json(), status=resp.status_code)
                except Exception:
                    return Response({"error": "http_error", "detail": str(e)}, status=resp.status_code)
            return Response({"error": "http_error", "detail": str(e)}, status=500)

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
                    "client_id": "admin-api",
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

