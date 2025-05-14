import logging
from datetime import datetime, timedelta
from keycloak import KeycloakAdmin
from django.conf import settings

logger = logging.getLogger(__name__)

_cached_admin = None
_cached_admin_expiry = None
_CACHE_TTL = timedelta(minutes=5)


def get_keycloak_admin() -> KeycloakAdmin:
    global _cached_admin, _cached_admin_expiry

    now = datetime.utcnow()
    if _cached_admin and _cached_admin_expiry and now < _cached_admin_expiry:
        return _cached_admin

    try:
        logger.info("[keycloak] Создаётся новый KeycloakAdmin")
        _cached_admin = KeycloakAdmin(
            server_url=f"{settings.KEYCLOAK_URL}/",
            realm_name=settings.KEYCLOAK_REALM,
            client_id=settings.KEYCLOAK_ADMIN_CLIENT_ID,
            client_secret_key=settings.KEYCLOAK_ADMIN_SECRET,
            verify=True,
        )
        _cached_admin_expiry = now + _CACHE_TTL
        return _cached_admin
    except Exception as e:
        logger.warning(f"[keycloak] Ошибка инициализации KeycloakAdmin: {e}")
        if _cached_admin:
            logger.warning("[keycloak] Используем устаревший кэш")
            return _cached_admin
        raise


def reset_keycloak_admin_cache():
    global _cached_admin, _cached_admin_expiry
    _cached_admin = None
    _cached_admin_expiry = None
    logger.info("[keycloak] Кэш KeycloakAdmin очищен вручную")
