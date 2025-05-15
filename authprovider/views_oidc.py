import json
import logging
from urllib.parse import urlencode
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import now
from datetime import datetime, timezone
from django.conf import settings
from jwt.exceptions import InvalidTokenError

from .utils.jwt_utils import sign_id_token, verify_id_token, load_public_key_components
from .utils.client_check import is_valid_client, get_client_config, is_valid_redirect_uri
from .utils.auth_code_store import get_auth_code, is_auth_code_used, mark_auth_code_as_used

logger = logging.getLogger(__name__)


def well_known(request):
    issuer = request.build_absolute_uri("/").rstrip("/")
    return JsonResponse({
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "password"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "id_token_signing_alg_values_supported": ["RS256"]
    })


def authorize(request):
    client_id = request.GET.get("client_id")
    redirect_uri = request.GET.get("redirect_uri")
    state = request.GET.get("state")
    nonce = request.GET.get("nonce")
    response_type = request.GET.get("response_type", "code")
    scope = request.GET.get("scope", "")

    if not all([client_id, redirect_uri, state, nonce]):
        logger.warning(f"[authorize] Отсутствуют обязательные параметры")
        return HttpResponseBadRequest("Missing required parameters")

    if response_type != "code":
        logger.warning(f"[authorize] Неподдерживаемый response_type: {response_type}")
        return HttpResponseBadRequest("Unsupported response_type")

    if "openid" not in scope:
        logger.warning(f"[authorize] Отсутствует 'openid' в scope: {scope}")
        return HttpResponseBadRequest("Missing 'openid' in scope")

    if not is_valid_redirect_uri(client_id, redirect_uri):
        logger.warning(f"[authorize] Недопустимый redirect_uri для клиента {client_id}: {redirect_uri}")
        return HttpResponseBadRequest("Invalid redirect_uri")

    return redirect(f"/login/?{urlencode(request.GET)}")


@csrf_exempt
def token(request):
    logger.info("[token] Запрос на /token: %s", request.POST.dict())

    client_id = request.POST.get("client_id")
    client_secret = request.POST.get("client_secret")

    if not is_valid_client(client_id, client_secret):
        logger.warning(f"[token] Неверный client_id или client_secret: {client_id}")
        return JsonResponse({"error": "invalid_client"}, status=401)

    grant_type = request.POST.get("grant_type")

    if grant_type == "authorization_code":
        code = request.POST.get("code")

        if is_auth_code_used(code):
            logger.warning(f"[token] Повторное использование кода: {code}")
            return JsonResponse({"error": "reused_code"}, status=400)

        user = get_auth_code(code, delete=True)
        if not user:
            logger.warning(f"[token] Код не найден или истёк: {code}")
            return JsonResponse({"error": "invalid_grant"}, status=400)

        if user["exp"] < datetime.now(timezone.utc):
            logger.warning(f"[token] Истёк срок действия кода: {code}")
            return JsonResponse({"error": "expired_code"}, status=400)

        mark_auth_code_as_used(code)

        logger.info(f"[token] Выдача токенов для sub={user['sub']}, client_id={client_id}")
        access_token = sign_id_token(user["sub"], user["name"], aud=client_id)
        id_token = sign_id_token(user["sub"], user["name"], aud=client_id, nonce=user.get("nonce"))

        return JsonResponse({
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "bearer",
            "expires_in": 300
        })

    elif grant_type == "password":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if username == "test" and password == "test":
            logger.info(f"[token] Тестовый вход для пользователя: {username}")
            return JsonResponse({
                "access_token": "test-access-token",
                "id_token": "test-id-token",
                "token_type": "Bearer",
                "expires_in": 3600
            })

        logger.warning(f"[token] Ошибка входа по паролю для: {username}")
        return JsonResponse({"error": "invalid_grant"}, status=400)

    logger.warning(f"[token] Неподдерживаемый grant_type: {grant_type}")
    return JsonResponse({"error": "unsupported_grant_type"}, status=400)


def userinfo(request):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()

    if not token:
        return JsonResponse({"error": "missing_token"}, status=401)

    try:
        decoded = verify_id_token(token, expected_aud=None)  # передай client_id, если он есть
        return JsonResponse({
            "sub": decoded.get("sub"),
            "preferred_username": decoded.get("sub"),
            "email": decoded.get("email", f"{decoded.get('sub')}@example.com"),
            "name": decoded.get("name", "Unknown")
        })

    except InvalidTokenError as e:
        logger.warning(f"[userinfo] Невалидный токен: {e}")
        return JsonResponse({"error": "invalid_token", "detail": str(e)}, status=401)


def jwks(request):
    logger.info("[jwks] Запрос на /jwks")
    jwk = load_public_key_components()
    return JsonResponse({"keys": [jwk]})


def login_view(request):
    required_params = ["client_id", "redirect_uri", "state", "nonce"]
    missing = [param for param in required_params if not request.GET.get(param)]

    if missing:
        logger.warning(f"[login_view] Не хватает параметров: {missing}")
        return render(request, "sso/error.html", {
            "message": "Недостаточно параметров в URL запроса.",
            "missing": missing,
        }, status=400)

    return render(request, "sso/login.html", {
        "client_id": request.GET["client_id"],
        "redirect_uri": request.GET["redirect_uri"],
        "state": request.GET["state"],
        "nonce": request.GET["nonce"],
    })


def set_password_view(request):
    return render(request, "sso/set_password.html", {
        "id_token": request.GET.get("id_token")
    })

def forgot_password_view(request):
    client_id = request.GET.get("client_id")
    redirect_uri = request.GET.get("redirect_uri")
    state = request.GET.get("state")

    if not all([client_id, redirect_uri, state]):
        return HttpResponseBadRequest("Missing required parameters")

    return render(request, "sso/forgot_password.html", {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
    })
