import logging
import requests
from django.conf import settings
from typing import Optional

logger = logging.getLogger(__name__)


def fetch_user_from_orleu(iin: str) -> Optional[dict]:
    try:
        response = requests.get(
            f"{settings.ORLEU_API}?iin={iin}",
            headers={"Authorization": f"Bearer {settings.ORLEU_API_TOKEN}"},
            timeout=5
        )
        response.raise_for_status()

        data = response.json()

        if isinstance(data, list) and data:
            return data[0]

        logger.warning(f"[orleu] Неожиданный формат ответа: {data}")
        return None

    except requests.HTTPError as e:
        logger.warning(f"[orleu] Ошибка HTTP {e.response.status_code}: {e.response.text}")
    except requests.RequestException as e:
        logger.warning(f"[orleu] Ошибка запроса: {e}")
    except Exception as e:
        logger.exception(f"[orleu] Ошибка при разборе ответа: {e}")

    return None
