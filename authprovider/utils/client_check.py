import logging
import hmac
from urllib.parse import urlparse
from django.conf import settings

logger = logging.getLogger(__name__)


def get_client_config(client_id: str) -> dict | None:
    """
    Возвращает конфиг клиента по client_id из settings.ALLOWED_CLIENTS
    """
    clients = getattr(settings, "ALLOWED_CLIENTS", {}) or {}
    return clients.get(client_id)


def is_valid_client(client_id: str, client_secret: str | None = None) -> bool:
    """
    Проверяет client_id и client_secret. Поддерживает public и confidential clients.
    """
    client = get_client_config(client_id)
    if not client:
        logger.warning(f"[client_check] Неизвестный client_id: {client_id}")
        return False

    expected_secret = client.get("secret")

    if not expected_secret:  # public client
        return client_secret in (None, "")

    if client_secret and hmac.compare_digest(expected_secret, client_secret):
        return True

    logger.warning(f"[client_check] Неверный client_secret для client_id={client_id}")
    return False


def is_valid_redirect_uri(client_id: str, redirect_uri: str) -> bool:
    """
    Проверяет, что redirect_uri входит в список разрешённых для клиента.
    """
    if not redirect_uri or not isinstance(redirect_uri, str):
        logger.warning(f"[client_check] redirect_uri невалиден: {redirect_uri}")
        return False

    parsed = urlparse(redirect_uri)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        logger.warning(f"[client_check] redirect_uri имеет недопустимую схему: {redirect_uri}")
        return False

    client = get_client_config(client_id)
    if not client:
        logger.warning(f"[client_check] Попытка с неизвестным client_id: {client_id}")
        return False

    allowed_uris = client.get("redirect_uris", [])
    if redirect_uri in allowed_uris:
        return True

    logger.warning(f"[client_check] Запрещённый redirect_uri для {client_id}: {redirect_uri}")
    return False
