import logging
from keycloak.exceptions import KeycloakGetError, KeycloakPostError
from .client import get_keycloak_admin
from ..ebdp.orleu import fetch_user_from_orleu

logger = logging.getLogger(__name__)


def get_user_id(iin: str, kc) -> str | None:
    try:
        users = kc.get_users(query={"username": iin})
        if users:
            return users[0]["id"]
    except KeycloakGetError as e:
        logger.warning(f"[keycloak] Ошибка поиска {iin}: {e}")
    return None


def parse_full_name(full_name: str) -> tuple[str, str]:
    parts = full_name.strip().split()
    return parts[1] if len(parts) > 1 else "", parts[0] if len(parts) > 0 else ""


def create_user(iin: str, full_name: str, email: str | None, kc) -> str | None:
    first, last = parse_full_name(full_name)
    payload = {
        "username": iin,
        "enabled": True,
        "firstName": first,
        "lastName": last,
        "email": email,
        "emailVerified": True,
    }

    try:
        kc.create_user(payload)
    except KeycloakPostError as e:
        if "409" in str(e):
            logger.warning(f"[keycloak] Пользователь {iin} уже существует (409)")
            return get_user_id(iin, kc)
        logger.exception(f"[keycloak] Ошибка создания {iin}: {e}")
        return None
    except Exception as e:
        logger.exception(f"[keycloak] Ошибка создания {iin}: {e}")
        return None

    return get_user_id(iin, kc)


def bind_user_to_idp(user_id: str, iin: str, kc):
    try:
        kc.add_user_social_login(
            user_id=user_id,
            provider_id="sso-entry",
            provider_userid=iin,
            provider_username=iin,
        )
        logger.info(f"[keycloak] IdP 'sso-entry' привязан к {iin}")
    except Exception as e:
        logger.warning(f"[keycloak] Ошибка привязки IdP: {e}")


def assign_roles(user_id: str, role_names: list[str], kc):
    try:
        all_roles = kc.get_realm_roles()
        role_map = {r["name"]: r for r in all_roles}

        assigned = []
        for role in role_names:
            r = role_map.get(role)
            if r:
                kc.assign_realm_roles(user_id, [r])
                assigned.append(role)

        if assigned:
            logger.info(f"[keycloak] Назначены роли {assigned} для {user_id}")
    except Exception as e:
        logger.warning(f"[keycloak] Ошибка назначения ролей {role_names}: {e}")


def create_or_get_user(iin: str, full_name: str) -> str | None:
    kc = get_keycloak_admin()

    user_id = get_user_id(iin, kc)
    if user_id:
        logger.info(f"[keycloak] Пользователь найден: {iin} (ID={user_id})")
        return user_id

    user_info = fetch_user_from_orleu(iin)
    if not user_info:
        logger.warning(f"[keycloak] ИИН {iin} не найден в ORLEU API")
        return None

    email = user_info.get("email")
    roles = user_info.get("roles", [])

    user_id = create_user(iin, full_name, email, kc)
    if not user_id:
        return None

    bind_user_to_idp(user_id, iin, kc)

    if roles:
        assign_roles(user_id, roles, kc)

    return user_id

def check_password_exists(username: str) -> bool:
    kc = get_keycloak_admin()
    users = kc.get_users(query={"username": username})
    if not users:
        return False

    creds = kc.get_credentials(users[0]["id"])
    for cred in creds:
        if cred.get("type") == "password":
            return True
    return False
