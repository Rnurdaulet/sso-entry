import json
import logging
from datetime import datetime, timedelta, timezone

import redis
from django.conf import settings

logger = logging.getLogger(__name__)
redis_client = redis.StrictRedis.from_url(settings.REDIS_URL, decode_responses=True)


def _make_key(code: str) -> str:
    return f"auth_code:{code}"


def _make_used_key(code: str) -> str:
    return f"used_code:{code}"


def save_auth_code(code: str, data: dict, ttl: int = 300):
    try:
        if not code.startswith("code-"):
            raise ValueError("Invalid code format")

        data = data.copy()
        if isinstance(data.get("exp"), datetime):
            data["exp"] = data["exp"].isoformat()

        redis_client.setex(_make_key(code), ttl, json.dumps(data))
        logger.info(f"[auth_code] Сохранён код: {code}")
    except Exception as e:
        logger.exception(f"[auth_code] Ошибка при сохранении кода: {e}")


def get_auth_code(code: str, delete: bool = True, mark_used: bool = True) -> dict | None:
    try:
        if not code.startswith("code-"):
            logger.warning(f"[auth_code] Неверный формат кода: {code}")
            return None

        if is_auth_code_used(code):
            return None

        key = _make_key(code)
        raw = redis_client.get(key)
        if not raw:
            logger.info(f"[auth_code] Код {code} не найден или истёк")
            return None

        if delete:
            redis_client.delete(key)

        data = json.loads(raw)

        if "exp" in data:
            try:
                data["exp"] = datetime.fromisoformat(data["exp"])
                if data["exp"].tzinfo is None:
                    data["exp"] = data["exp"].replace(tzinfo=timezone.utc)
            except ValueError:
                logger.warning(f"[auth_code] Невалидный формат exp, сброс: {code}")
                data["exp"] = datetime.now(timezone.utc) - timedelta(seconds=1)

            if data["exp"] < datetime.now(timezone.utc):
                logger.warning(f"[auth_code] Код {code} истёк по exp")
                return None

        logger.info(f"[auth_code] Получен код: {code}")

        if mark_used:
            mark_auth_code_as_used(code)

        return data

    except Exception as e:
        logger.exception(f"[auth_code] Ошибка при получении кода {code}: {e}")
        return None


def mark_auth_code_as_used(code: str, ttl: int = 300):
    try:
        redis_client.setex(_make_used_key(code), ttl, "1")
        logger.info(f"[auth_code] Помечен как использованный: {code}")
    except Exception as e:
        logger.warning(f"[auth_code] Ошибка при пометке used_code: {e}")


def is_auth_code_used(code: str) -> bool:
    try:
        used = redis_client.exists(_make_used_key(code)) == 1
        if used:
            logger.warning(f"[auth_code] Повторное использование кода: {code}")
        return used
    except Exception as e:
        logger.warning(f"[auth_code] Redis check failed: {e}")
        return False
