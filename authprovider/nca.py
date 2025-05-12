import requests
from requests.auth import HTTPBasicAuth

NCANODE_URL = "https://nca.odx.kz/cms/verify" # локальный mock
NCANODE_BASIC_USER = "admin"
NCANODE_BASIC_PASS = "Alohomora999@"

def verify_ecp_signature(signed_data: str, nonce: str) -> tuple[str, str]:
    resp = requests.post(
        NCANODE_URL,
        json={
            "cms": signed_data,
            "revocationCheck": ["OCSP"],
            "data": nonce
        },
        auth=HTTPBasicAuth(NCANODE_BASIC_USER, NCANODE_BASIC_PASS),
        timeout=10
    )
    resp.raise_for_status()
    result = resp.json()

    if not result.get("valid"):
        raise Exception("Подпись недействительна")

    signer = result["signers"][0]["certificates"][0]["subject"]
    return signer["iin"], signer["commonName"]
