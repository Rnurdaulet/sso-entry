from django.http import JsonResponse, HttpResponseRedirect, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from urllib.parse import urlencode
from django.conf import settings
from .nca import verify_ecp_signature
from .keycloak import create_or_get_user, sign_id_token, is_valid_client
from .auth_code_store import save_auth_code, get_auth_code
from jwt.utils import base64url_encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import secrets
import json

def log(msg, data=None):
    print(f"[SSO-PROXY] {msg}")
    if data is not None:
        print(json.dumps(data, indent=2, ensure_ascii=False))

def well_known(request):
    log("Запрос на /.well-known/openid-configuration")
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
    log("Запрос на /authorize", request.GET.dict())

    client_id = request.GET.get("client_id")
    redirect_uri = request.GET.get("redirect_uri")
    state = request.GET.get("state")
    signed_data = request.GET.get("signed_data")
    nonce = request.GET.get("nonce")

    if not all([client_id, redirect_uri, state, signed_data, nonce]):
        log("Ошибка: отсутствуют обязательные параметры")
        return HttpResponseBadRequest("Missing required parameters")

    try:
        iin, name = verify_ecp_signature(signed_data, nonce)
        log("Успешная проверка ЭЦП", {"iin": iin, "name": name})
        create_or_get_user(iin, name)
    except Exception as e:
        log("Ошибка подписи", {"exception": str(e)})
        return JsonResponse({"error": "invalid_signature", "error_description": str(e)}, status=400)

    code = f"code-{secrets.token_urlsafe(24)}"
    save_auth_code(code, {
        "sub": iin,
        "name": name,
        "client_id": client_id,
        "exp": datetime.utcnow() + timedelta(minutes=5)
    })

    log("Генерация кода авторизации", {"code": code, "redirect_uri": redirect_uri})
    redirect_params = urlencode({"code": code, "state": state})
    return HttpResponseRedirect(f"{redirect_uri}?{redirect_params}")

@csrf_exempt
def token(request):
    log("Запрос на /token", request.POST.dict())

    client_id = request.POST.get("client_id")
    client_secret = request.POST.get("client_secret")

    if not is_valid_client(client_id, client_secret):
        log("Неверный клиент", {"client_id": client_id})
        return JsonResponse({"error": "invalid_client"}, status=401)

    if request.POST.get("grant_type") == "authorization_code":
        code = request.POST.get("code")
        user = get_auth_code(code)
        if not user or user["exp"] < datetime.utcnow():
            log("Неверный или истекший код", {"code": code})
            return JsonResponse({"error": "invalid_grant"}, status=400)

        log("Выдача токена", {"sub": user["sub"], "client_id": client_id})
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
            log("Тестовый вход через пароль", {"username": username})
            return JsonResponse({
                "access_token": "password-token-test",
                "id_token": "id-token-test",
                "token_type": "Bearer",
                "expires_in": 3600
            })
        log("Ошибка пароля", {"username": username})
        return JsonResponse({"error": "invalid_grant"}, status=400)

    log("Неподдерживаемый grant_type", {"grant_type": request.POST.get("grant_type")})
    return JsonResponse({"error": "unsupported_grant_type"}, status=400)

def userinfo(request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    log("Запрос к /userinfo", {"access_token": token})

    if "access-token" in token or "password-token" in token:
        return JsonResponse({
            "sub": "010101010101",
            "name": "ИВАНОВ ИВАН"
        })
    return JsonResponse({"error": "invalid_token"}, status=401)

def jwks(request):
    log("Запрос на /jwks")
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
