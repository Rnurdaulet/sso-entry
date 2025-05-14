import requests
from keycloak import KeycloakAdmin, KeycloakGetError
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


import requests
from keycloak.exceptions import KeycloakGetError

def create_or_get_user(iin, full_name):
    keycloak_admin = get_keycloak_admin()

    # 🔍 1. Проверка: есть ли уже такой пользователь
    try:
        users = keycloak_admin.get_users(query={"username": iin})
        if users:
            print(f"[SSO-PROXY] Пользователь {iin} уже существует. ID = {users[0]['id']}")
            return users[0]["id"]
    except KeycloakGetError as e:
        print(f"[SSO-PROXY] Ошибка при поиске пользователя: {e}")
        return None

    # 🌐 2. Запрос к внешнему API
    try:
        api_resp = requests.get(
            f"{settings.ORLEU_API}?iin={iin}",
            headers={"Authorization": f"Bearer {settings.ORLEU_API_TOKEN}"}
        )
        api_resp.raise_for_status()
        data = api_resp.json()
        if not data:
            print(f"[SSO-PROXY] ИИН {iin} не найден во внешней базе")
            return None
        user_info = data[0]
        print(f"[SSO-PROXY] Данные из внешнего API: {user_info}")
    except Exception as e:
        print(f"[SSO-PROXY] Ошибка при запросе к внешнему API: {e}")
        return None

    # 👤 3. Разбор ФИО
    parts = full_name.strip().split()
    last_name = parts[0] if len(parts) > 0 else ""
    first_name = parts[1] if len(parts) > 1 else ""

    email = user_info.get("email")
    roles = user_info.get("roles", [])

    user_data = {
        "username": iin,
        "enabled": True,
        "firstName": first_name,
        "lastName": last_name,
        "email": email,
        "emailVerified": True
    }

    # 🆕 4. Создание пользователя
    try:
        keycloak_admin.create_user(user_data)
        # Повторный поиск, чтобы получить ID
        users = keycloak_admin.get_users(query={"username": iin})
        if not users:
            print(f"[SSO-PROXY] Не удалось найти созданного пользователя {iin}")
            return None
        user_id = users[0]["id"]
        print(f"[SSO-PROXY] Пользователь {iin} успешно создан. ID = {user_id}")
    except Exception as e:
        print(f"[SSO-PROXY] Ошибка при создании пользователя: {e}")
        return None

    # После получения user_id
    try:
        keycloak_admin.add_user_social_login(
            user_id=user_id,
            provider_id="sso-entry",
            provider_userid=iin,
            provider_username=iin
        )
        print(f"[SSO-PROXY] Успешно связали пользователя {iin} с IdP 'sso-entry'")
    except Exception as e:
        print(f"[SSO-PROXY] Ошибка при привязке IdP: {e}")

    # 5. Назначение роли (из realm-level roles)
    if roles:
        role_name = roles[0]
        try:
            available_roles = keycloak_admin.get_realm_roles()
            matched_role = next((r for r in available_roles if r["name"] == role_name), None)
            if matched_role:
                keycloak_admin.assign_realm_roles(user_id, [matched_role])
                print(f"[SSO-PROXY] Назначена роль {role_name} пользователю {iin} (realm role)")
            else:
                print(f"[SSO-PROXY] Роль {role_name} не найдена в realm")
        except Exception as e:
            print(f"[SSO-PROXY] Ошибка при назначении роли: {e}")

    return user_id

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
