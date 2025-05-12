from django.http import JsonResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from urllib.parse import urlencode
from django.conf import settings
from .nca import verify_ecp_signature
from .keycloak import create_or_get_user, sign_id_token, is_valid_client
import json
from jwt.utils import base64url_encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import secrets

from .auth_code_store import save_auth_code, get_auth_code

AUTH_CODE_STORE = {}

def well_known(request):
    return JsonResponse({
        "issuer": settings.OIDC_ISSUER,
        "authorization_endpoint": f"{settings.OIDC_ISSUER}/authorize",
        "token_endpoint": f"{settings.OIDC_ISSUER}/token",
        "userinfo_endpoint": f"{settings.OIDC_ISSUER}/userinfo",
        "jwks_uri": f"{settings.OIDC_ISSUER}/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "password"],
        "id_token_signing_alg_values_supported": ["RS256"]
    })

def authorize(request):
    client_id = request.GET.get("client_id")
    redirect_uri = request.GET.get("redirect_uri")
    state = request.GET.get("state")
    signed_data = request.GET.get("signed_data")
    nonce = request.GET.get("nonce")

    if not all([client_id, redirect_uri, state, signed_data, nonce]):
        return HttpResponseBadRequest("Missing required parameters")

    try:
        iin, name = verify_ecp_signature(signed_data, nonce)
        create_or_get_user(iin, name)
    except Exception as e:
        return JsonResponse({"error": "invalid_signature", "error_description": str(e)}, status=400)

    code = f"code-{secrets.token_urlsafe(24)}"
    save_auth_code(code, {
        "sub": iin,
        "name": name,
        "client_id": client_id,
        "exp": datetime.utcnow() + timedelta(minutes=5)
    })

    redirect_params = urlencode({"code": code, "state": state})
    return HttpResponseRedirect(f"{redirect_uri}?{redirect_params}")

@csrf_exempt
def token(request):
    client_id = request.POST.get("client_id")
    client_secret = request.POST.get("client_secret")

    if not is_valid_client(client_id, client_secret):
        return JsonResponse({"error": "invalid_client"}, status=401)

    if request.POST.get("grant_type") == "authorization_code":
        code = request.POST.get("code")
        user = get_auth_code(code)
        if not user or user["exp"] < datetime.utcnow():
            return JsonResponse({"error": "invalid_grant"}, status=400)

        id_token = sign_id_token(user["sub"], user["name"], aud=client_id)
        return JsonResponse({
            "access_token": f"access-token-{user['sub']}",
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600
        })

    elif request.POST.get("grant_type") == "password":
        username = request.POST.get("username")
        password = request.POST.get("password")
        if username == "test" and password == "test":
            return JsonResponse({
                "access_token": "password-token-test",
                "id_token": "id-token-test",
                "token_type": "Bearer",
                "expires_in": 3600
            })
        return JsonResponse({"error": "invalid_grant"}, status=400)

    return JsonResponse({"error": "unsupported_grant_type"}, status=400)

def userinfo(request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if "access-token" in token or "password-token" in token:
        return JsonResponse({
            "sub": "010101010101",
            "name": "ИВАНОВ ИВАН"
        })
    return JsonResponse({"error": "invalid_token"}, status=401)

def jwks(request):
    with open("rsa-public.pem", "rb") as f:
        pub = serialization.load_pem_public_key(f.read(), backend=default_backend())

    numbers = pub.public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "default",
        "n": base64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")).decode(),
        "e": base64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")).decode(),
    }
    return JsonResponse({"keys": [jwk]})
