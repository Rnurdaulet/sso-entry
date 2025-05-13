import redis
import json
from datetime import datetime, timedelta

from django.conf import settings

redis_client = redis.StrictRedis.from_url(settings.REDIS_URL, decode_responses=True)

def save_auth_code(code, data, ttl=300):
    # Сериализуем datetime вручную
    data = data.copy()
    if isinstance(data.get("exp"), datetime):
        data["exp"] = data["exp"].isoformat()
    redis_client.setex(f"auth_code:{code}", ttl, json.dumps(data))
    print(f"auth_code:{code}")

def get_auth_code(code, delete=True):
    raw = redis_client.get(f"auth_code:{code}")
    if not raw:
        return None
    if delete:
        redis_client.delete(f"auth_code:{code}")
    data = json.loads(raw)
    if "exp" in data:
        data["exp"] = datetime.fromisoformat(data["exp"])
    print(f"auth_code:{code}")
    return data
