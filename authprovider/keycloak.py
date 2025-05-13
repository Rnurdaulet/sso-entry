import requests
import jwt
from django.conf import settings
from datetime import datetime, timedelta
import calendar

def get_admin_token():
    data = {
        "grant_type": "client_credentials",
        "client_id": "admin-api",
        "client_secret": settings.KEYCLOAK_ADMIN_SECRET
    }
    response = requests.post(
        f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token",
        data=data
    )

    response.raise_for_status()
    return response.json()["access_token"]
def create_or_get_user(iin, full_name):
    """ Ищет пользователя по username (iin), создаёт если не найден """
    token = get_admin_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Поиск
    resp = requests.get(
        f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users?username={iin}",
        headers=headers
    )
    resp.raise_for_status()
    users = resp.json()

    if users:
        return users[0]["id"]

    # Создание
    payload = {
        "username": iin,
        "enabled": True,
        "attributes": {"iin": [iin]},
        "firstName": full_name.split()[1],
        "lastName": full_name.split()[0],
    }

    create_resp = requests.post(
        f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users",
        headers=headers,
        json=payload
    )
    create_resp.raise_for_status()

    # Повторный поиск — чтобы вернуть ID
    return create_or_get_user(iin, full_name)
def sign_id_token(sub, name, aud, nonce=None):
    """ Подписывает id_token по OIDC (RS256) с поддержкой nonce """
    with open(settings.PRIVATE_KEY_PATH, "rb") as f:
        private_key = f.read()

    now = datetime.utcnow()
    payload = {
        "iss": settings.OIDC_ISSUER,
        "sub": sub,
        "aud": aud,
        "name": name,
        "iat": calendar.timegm(now.utctimetuple()),
        "exp": calendar.timegm((now + timedelta(hours=1)).utctimetuple()),
    }

    if nonce:
        payload["nonce"] = nonce  # 👈 ключевая строка

    return jwt.encode(payload, private_key, algorithm="RS256")
def is_valid_client(*args, **kwargs):
    return True
