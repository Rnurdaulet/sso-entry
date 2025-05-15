import jwt
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from django.conf import settings
from jwt import InvalidTokenError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jwt.utils import base64url_encode

logger = logging.getLogger(__name__)

_cached_private_key = None
_cached_public_key = None
_cached_kid = None


def get_private_key():
    global _cached_private_key
    if _cached_private_key is None:
        try:
            with open(settings.PRIVATE_KEY_PATH, "rb") as f:
                _cached_private_key = f.read()
        except Exception as e:
            logger.critical(f"[jwt] Ошибка загрузки приватного ключа: {e}")
            raise RuntimeError("Невозможно загрузить приватный ключ")
    return _cached_private_key


def get_public_key():
    global _cached_public_key
    if _cached_public_key is None:
        try:
            private_key = serialization.load_pem_private_key(
                get_private_key(),
                password=None,
                backend=default_backend()
            )
            _cached_public_key = private_key.public_key()
        except Exception as e:
            logger.critical(f"[jwt] Ошибка извлечения публичного ключа: {e}")
            raise RuntimeError("Невозможно загрузить публичный ключ")
    return _cached_public_key


def _get_kid() -> str:
    global _cached_kid
    if _cached_kid is None:
        pub_key = get_public_key()
        numbers = pub_key.public_numbers()
        n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        kid_raw = hashlib.sha1(n_bytes).digest()
        _cached_kid = base64url_encode(kid_raw).decode()[:10]
    return _cached_kid


def sign_id_token(
    sub: str,
    name: str,
    aud: str,
    nonce: str = None,
    extra: dict | None = None
) -> str:
    now = datetime.now(timezone.utc)
    now_ts = int(now.timestamp())

    payload = {
        "iss": settings.OIDC_ISSUER,
        "sub": sub,
        "aud": aud,
        "name": name,
        "iat": now_ts,
        "exp": now_ts + 300,
    }

    if nonce:
        payload["nonce"] = nonce

    if extra:
        payload.update(extra)

    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": _get_kid(),
    }

    try:
        token = jwt.encode(
            payload,
            get_private_key(),
            algorithm="RS256",
            headers=headers
        )
        logger.info(f"[jwt] Сгенерирован id_token для sub={sub}")
        return token
    except Exception as e:
        logger.error(f"[jwt] Ошибка генерации токена: {e}")
        raise



def verify_id_token(token: str, expected_aud: str | None = None) -> dict:
    try:
        options = {
            "require": ["exp", "iat", "aud"],
            "verify_aud": bool(expected_aud),
        }

        decoded = jwt.decode(
            token,
            key=get_public_key(),
            algorithms=["RS256"],
            audience=expected_aud,
            options=options
        )

        logger.info(f"[jwt] Токен прошёл проверку: sub={decoded.get('sub')}")
        return decoded

    except InvalidTokenError as e:
        logger.warning(f"[jwt] Токен недействителен: {e}")
        raise
    except Exception as e:
        logger.exception(f"[jwt] Критическая ошибка при верификации токена: {e}")
        raise


def load_public_key_components() -> dict:
    """
    Генерирует валидный JWK-объект для /.well-known/jwks
    """
    try:
        pub_key = get_public_key()
        numbers = pub_key.public_numbers()

        n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")

        n = base64url_encode(n_bytes).decode()
        e = base64url_encode(e_bytes).decode()

        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": _get_kid(),
            "n": n,
            "e": e,
        }

    except Exception as e:
        logger.critical(f"[jwt] Ошибка генерации jwk: {e}")
        raise RuntimeError("JWK generation failed")
