import logging
from datetime import timedelta
from keycloak import KeycloakAdmin, KeycloakOpenID
from django.conf import settings
from cachetools import TTLCache, cached
import threading

logger = logging.getLogger(__name__)

# ————— Кеши и блокировки —————
_admin_cache = TTLCache(maxsize=1, ttl=300)  # 5 минут
_openid_cache = TTLCache(maxsize=1, ttl=300)
_admin_lock = threading.Lock()
_openid_lock = threading.Lock()

# ————— Admin-клиент —————

@cached(_admin_cache, lock=_admin_lock)
def _create_keycloak_admin() -> KeycloakAdmin:
    logger.info("[keycloak] Создание нового KeycloakAdmin клиента")
    return KeycloakAdmin(
        server_url=settings.KEYCLOAK_URL.rstrip("/") + "/",
        realm_name=settings.KEYCLOAK_REALM,
        client_id=settings.KEYCLOAK_ADMIN_CLIENT_ID,
        client_secret_key=settings.KEYCLOAK_ADMIN_SECRET,
        verify=True,
    )

def get_keycloak_admin() -> KeycloakAdmin:
    try:
        return _create_keycloak_admin()
    except Exception as e:
        logger.error(f"[keycloak] Ошибка при инициализации KeycloakAdmin: {e}")
        _admin_cache.clear()
        raise


# ————— OpenID-клиент —————

@cached(_openid_cache, lock=_openid_lock)
def _create_keycloak_openid() -> KeycloakOpenID:
    logger.info("[keycloak] Создание нового KeycloakOpenID клиента")
    return KeycloakOpenID(
        server_url=settings.KEYCLOAK_URL.rstrip("/") + "/",
        realm_name=settings.KEYCLOAK_REALM,
        client_id=settings.KEYCLOAK_CLIENT_ID,
        client_secret_key=settings.KEYCLOAK_CLIENT_SECRET,
        verify=True,
    )

def get_keycloak_openid() -> KeycloakOpenID:
    try:
        return _create_keycloak_openid()
    except Exception as e:
        logger.error(f"[keycloak] Ошибка при инициализации KeycloakOpenID: {e}")
        _openid_cache.clear()
        raise


# ————— Ручной сброс кеша (по необходимости) —————

def reset_keycloak_admin_cache() -> None:
    _admin_cache.clear()
    logger.info("[keycloak] Кеш KeycloakAdmin очищен вручную")

def reset_keycloak_openid_cache() -> None:
    _openid_cache.clear()
    logger.info("[keycloak] Кеш KeycloakOpenID очищен вручную")
