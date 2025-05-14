from keycloak import KeycloakAdmin
from jwt import encode as jwt_encode
from datetime import datetime, timedelta
import calendar
from django.conf import settings


def get_keycloak_admin():
    return KeycloakAdmin(
        server_url=f"{settings.KEYCLOAK_URL}/",
        realm_name=settings.KEYCLOAK_REALM,
        client_id=settings.KEYCLOAK_ADMIN_CLIENT_ID,
        client_secret_key=settings.KEYCLOAK_ADMIN_SECRET,
        verify=False  # или False если без HTTPS
    )


def create_or_get_user(iin, full_name):
    keycloak_admin = get_keycloak_admin()

    users = keycloak_admin.get_users(query={"username": iin})
    if users:
        return users[0]["id"]

    first_name = full_name.split()[1] if len(full_name.split()) > 1 else full_name
    last_name = full_name.split()[0]

    user_data = {
        "username": iin,
        "enabled": True,
        "firstName": first_name,
        "lastName": last_name,
        "attributes": {"iin": [iin]}
    }

    keycloak_admin.create_user(user_data)

    # Получаем ID созданного пользователя
    users = keycloak_admin.get_users(query={"username": iin})
    return users[0]["id"] if users else None


def sign_id_token(sub, name, aud, nonce=None):
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
        payload["nonce"] = nonce

    return jwt_encode(payload, private_key, algorithm="RS256")


def is_valid_client(*args, **kwargs):
    return True
