import requests
import logging
from requests.auth import HTTPBasicAuth
from django.conf import settings

logger = logging.getLogger(__name__)

NCANODE_URL = getattr(settings, "NCANODE_URL", "http://nca.odx.kz/cms/verify")
NCANODE_BASIC_USER = getattr(settings, "NCANODE_BASIC_USER", "admin")
NCANODE_BASIC_PASS = getattr(settings, "NCANODE_BASIC_PASS", "Alohomora999@")


def verify_ecp_signature(signed_data: str, nonce: str) -> tuple[str, str]:
    """
    Проверка подписи через NCANode.
    Возвращает (IIN, Common Name) или выбрасывает Exception.
    """
    try:
        response = requests.post(
            NCANODE_URL,
            json={
                "cms": signed_data,
                "revocationCheck": ["OCSP"],
                "data": nonce
            },
            auth=HTTPBasicAuth(NCANODE_BASIC_USER, NCANODE_BASIC_PASS),
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()

        if not result.get("valid"):
            logger.warning("[nca] Подпись недействительна для nonce=%s", nonce)
            raise Exception("Подпись недействительна")

        signers = result.get("signers", [])
        if not signers or not signers[0].get("certificates"):
            logger.error("[nca] Нет подписантов или сертификатов в ответе NCANode")
            raise Exception("Подписант или сертификат не найден")

        subject = signers[0]["certificates"][0].get("subject", {})
        iin = subject.get("iin")
        name = subject.get("commonName")

        if not iin or not (iin.isdigit() and len(iin) == 12):
            logger.error("[nca] Некорректный IIN: %s", iin)
            raise Exception("Некорректный IIN в сертификате")

        if not name:
            logger.error("[nca] Common Name отсутствует в сертификате")
            raise Exception("Не удалось извлечь имя из сертификата")

        logger.info("[nca] Подпись подтверждена: %s (%s)", iin, name)
        return iin, name

    except requests.RequestException as e:
        logger.exception("[nca] Ошибка запроса к NCANode")
        raise Exception(f"Ошибка запроса к NCANode: {e}")

    except Exception as e:
        logger.exception("[nca] Ошибка проверки подписи")
        raise Exception(f"Ошибка проверки подписи: {e}")
