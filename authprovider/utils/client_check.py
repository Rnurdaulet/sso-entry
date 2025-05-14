import logging
from django.conf import settings

logger = logging.getLogger(__name__)


def get_client_config(client_id: str) -> dict | None:
    """
    Возвращает конфиг клиента по client_id.
    Формат должен быть в settings.ALLOWED_CLIENTS:
    {
        "client_id_1": {
            "secret": "supersecret",
            "redirect_uris": ["http://localhost:3000/callback"]
        },
        ...
    }
    """
    clients = getattr(settings, "ALLOWED_CLIENTS", {})
    return clients.get(client_id)


def is_valid_client(client_id: str, client_secret: str | None = None) -> bool:
    """
    Проверяет client_id + client_secret.
    Если client_secret не задан — возвращает True только если клиент не требует секрет.
    """
    client = get_client_config(client_id)
    if not client:
        logger.warning(f"[client_check] Неизвестный client_id: {client_id}")
        return False

    expected_secret = client.get("secret")

    if expected_secret is None:
        return True

    if expected_secret == client_secret:
        return True

    logger.warning(f"[client_check] Неверный client_secret для: {client_id}")
    return False


def is_valid_redirect_uri(client_id: str, redirect_uri: str) -> bool:
    """
    Проверяет, что redirect_uri разрешён для указанного клиента.
    """
    client = get_client_config(client_id)
    if not client:
        logger.warning(f"[client_check] Попытка с неизвестным client_id: {client_id}")
        return False

    allowed_uris = client.get("redirect_uris", [])
    if redirect_uri in allowed_uris:
        return True

    logger.warning(f"[client_check] Запрещённый redirect_uri для {client_id}: {redirect_uri}")
    return False
