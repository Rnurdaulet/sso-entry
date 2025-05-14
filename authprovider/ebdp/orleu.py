import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def fetch_user_from_orleu(iin: str) -> dict | None:
    try:
        r = requests.get(
            f"{settings.ORLEU_API}?iin={iin}",
            headers={"Authorization": f"Bearer {settings.ORLEU_API_TOKEN}"},
            timeout=5
        )
        r.raise_for_status()
        users = r.json()
        return users[0] if users else None
    except Exception as e:
        logger.warning(f"[orleu] Ошибка при запросе: {e}")
        return None
