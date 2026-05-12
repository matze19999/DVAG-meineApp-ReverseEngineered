import getpass
import base64
import hashlib
import hmac
import json
import os
import platform
import requests
import sys
import time
import uuid
from typing import Any
from urllib.parse import quote


BASE_URL = "https://meinportal.dvag"
TOKEN_URL = f"{BASE_URL}/auth/realms/DVAG/protocol/openid-connect/token"

CLIENT_ID = "kundenportal"
SETUP_CLIENT_ID = "setupkundenportal"
CLIENT_VERSION = "1.32.1"
ANDROID_APP_ID = "com.dvag.meineapp"
TOKEN_CACHE_FILE = "meineapp_token_cache.json"


def base64url(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")


def decode_jwt(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))


def access_token_is_valid(token: str, leeway_seconds: int = 60) -> bool:
    try:
        decoded = decode_jwt(token)
        return int(decoded.get("exp", 0)) > int(time.time()) + leeway_seconds
    except Exception:
        return False


def app_info(timestamp: int, device_secret: str | None = None) -> dict[str, Any]:
    info = {
        "device.model": platform.machine() or "unknown",
        "device.cordova": "4.5.5",
        "device.platform": "Android",
        "device.uuid": ANDROID_APP_ID,
        "device.version": platform.platform(),
        "device.manufacturer": platform.node() or "unknown",
        "device.isVirtual": False,
        "date": timestamp,
    }
    if device_secret:
        info["device.secret"] = device_secret
    return info


def generate_device_secret() -> str:
    return str(uuid.uuid4())


def build_signed_appid(username: str, secret: str, signing_key: str | None = None) -> str:
    signing_key = signing_key or secret
    timestamp = int(time.time() * 1000)
    info_part = base64url(json.dumps(app_info(timestamp, secret if signing_key != secret else None), separators=(",", ":")).encode("utf-8"))
    signature_input = f"{ANDROID_APP_ID};{username.lower()};{timestamp};{signing_key}"
    digest = hmac.new(signing_key.encode("utf-8"), signature_input.encode("utf-8"), hashlib.sha256).digest()
    return f"{info_part};{base64url(digest)}"


def request_token(username: str, password: str, client_id: str, app_secret: str | None = None) -> requests.Response:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    if client_id == CLIENT_ID:
        headers["ClientVersion"] = CLIENT_VERSION
        if app_secret:
            headers["appid"] = build_signed_appid(username, app_secret)

    data = {
        "grant_type": "password",
        "client_id": client_id,
        "username": username.lower() if client_id == SETUP_CLIENT_ID else username,
        "password": password,
    }

    return requests.post(
        TOKEN_URL,
        headers=headers,
        data=data,
        timeout=30,
    )


def refresh_token(username: str, refresh_token_value: str, app_secret: str | None = None) -> requests.Response:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "ClientVersion": CLIENT_VERSION,
    }
    if app_secret:
        headers["appid"] = build_signed_appid(username, app_secret)

    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "username": username.lower(),
        "refresh_token": refresh_token_value,
    }

    return requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)


def load_token_cache() -> dict | None:
    if not os.path.exists(TOKEN_CACHE_FILE):
        return None
    with open(TOKEN_CACHE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_token_cache(username: str, token_data: dict, app_secret: str | None = None) -> None:
    cache = {
        "username": username,
        "app_secret": app_secret or os.getenv("MEINEAPP_APP_SECRET"),
        "token_data": token_data,
    }
    with open(TOKEN_CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    os.chmod(TOKEN_CACHE_FILE, 0o600)


def get_cached_or_refreshed_token() -> dict | None:
    cache = load_token_cache()
    if not cache:
        return None

    token_data = cache.get("token_data") or {}
    access_token = token_data.get("access_token")
    if access_token and access_token_is_valid(access_token):
        print("Nutze gespeicherten Bearer Token.")
        return token_data

    username = cache.get("username")
    refresh_token_value = token_data.get("refresh_token")
    if not username or not refresh_token_value:
        return None

    response = refresh_token(username, refresh_token_value, cache.get("app_secret"))
    if response.status_code != 200:
        print("Token-Refresh fehlgeschlagen, Login erforderlich.")
        print("HTTP Status:", response.status_code)
        print(response.text)
        return None

    refreshed = response.json()
    save_token_cache(username, refreshed, cache.get("app_secret"))
    print("Bearer Token per Refresh erneuert.")
    return refreshed


def login(username: str, password: str) -> dict:
    response = request_token(username, password, CLIENT_ID, os.getenv("MEINEAPP_APP_SECRET"))

    if response.status_code != 200:
        setup_token_data = maybe_run_appid_setup(username, password, response)
        if setup_token_data:
            return setup_token_data
        print("Login fehlgeschlagen")
        print("HTTP Status:", response.status_code)
        print("Antwort:")
        print(response.text)
        sys.exit(1)

    return response.json()


def auth_headers(access_token: str, content_type: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "ClientVersion": CLIENT_VERSION,
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def get_json(access_token: str, path: str, params: dict[str, str] | None = None) -> dict:
    response = requests.get(
        f"{BASE_URL}{path}",
        headers=auth_headers(access_token),
        params=params,
        timeout=30,
    )
    if response.status_code != 200:
        print("API-Aufruf fehlgeschlagen")
        print("URL:", response.url)
        print("HTTP Status:", response.status_code)
        print(response.text)
        sys.exit(1)
    return response.json()


def fetch_financial_overview(access_token: str, zuordnung: str = "MEINE") -> dict:
    portos_id = decode_jwt(access_token)["sub"]
    return get_json(
        access_token,
        "/vertrag/rest/v1/uebersichten",
        {"portosId": portos_id, "zuordnung": zuordnung},
    )


def save_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def maybe_run_appid_setup(username: str, password: str, failed_response: requests.Response) -> dict | None:
    try:
        error = failed_response.json().get("error")
    except ValueError:
        return None
    if error != "invalid_appid":
        return None

    print("Der Server verlangt eine registrierte AppId fuer dieses Konto.")
    answer = input("AppId jetzt per SMS registrieren? [j/N]: ").strip().lower()
    if answer not in {"j", "ja", "y", "yes"}:
        return None

    return setup_appid(username, password)


def setup_appid(username: str, password: str) -> dict:
    setup_response = request_token(username, password, SETUP_CLIENT_ID)
    if setup_response.status_code != 200:
        print("Setup-Login fehlgeschlagen")
        print("HTTP Status:", setup_response.status_code)
        print(setup_response.text)
        sys.exit(1)

    setup_tokens = setup_response.json()
    access_token = setup_tokens["access_token"]
    decoded = decode_jwt(access_token)
    portos_id = decoded["sub"]

    phone_response = requests.get(
        f"{BASE_URL}/kunde/rest/v2/kunden/{portos_id}/mobilnummern",
        headers=auth_headers(access_token),
        timeout=30,
    )
    print("Mobilnummern Status:", phone_response.status_code)
    print(phone_response.text)
    if phone_response.status_code >= 400:
        sys.exit(1)

    phone_numbers = phone_response.json()
    if len(phone_numbers) == 1:
        mobile_number = phone_numbers[0]
        print("Nutze Mobilnummer:", mobile_number)
    else:
        mobile_number = input("Mobilnummer exakt aus der Antwort eingeben: ").strip()
    encoded_mobile_number = quote(mobile_number, safe="")
    sms_response = requests.post(
        f"{BASE_URL}/registrierer/rest/v4/kunden/{portos_id}/mobilnummern/{encoded_mobile_number}/smscodes",
        headers=auth_headers(access_token),
        timeout=30,
    )
    print("SMS Status:", sms_response.status_code)
    if sms_response.text:
        print(sms_response.text)
    if sms_response.status_code >= 400:
        sys.exit(1)

    sms_code = input("SMS-Code: ").strip()
    device_secret = generate_device_secret()
    signed_app_info = build_signed_appid(username, device_secret, signing_key=sms_code)
    appid_response = requests.post(
        f"{BASE_URL}/registrierer/rest/v4/authentifizierung/appId",
        headers=auth_headers(access_token, "application/json"),
        json={
            "loginEmail": username,
            "portosId": portos_id,
            "signedAppInfo": signed_app_info,
        },
        timeout=30,
    )
    print("AppId Registrierung Status:", appid_response.status_code)
    if appid_response.text:
        print(appid_response.text)
    if appid_response.status_code >= 400:
        sys.exit(1)

    os.environ["MEINEAPP_APP_SECRET"] = device_secret
    print()
    print("AppId registriert. Fuer kuenftige Logins setzen:")
    print(f"export MEINEAPP_APP_SECRET='{device_secret}'")
    print()
    print("Versuche Login mit registrierter AppId ...")

    login_response = request_token(username, password, CLIENT_ID, device_secret)
    if login_response.status_code != 200:
        print("Login nach AppId-Registrierung fehlgeschlagen")
        print("HTTP Status:", login_response.status_code)
        print(login_response.text)
        sys.exit(1)
    token_data = login_response.json()
    save_token_cache(username, token_data, device_secret)
    return token_data


if __name__ == "__main__":
    token_data = get_cached_or_refreshed_token()

    if not token_data:
        username = input("Benutzername / E-Mail: ")
        password = getpass.getpass("Passwort: ")
        token_data = login(username, password)
        save_token_cache(username, token_data)

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")

    if not access_token:
        print("Kein access_token gefunden.")
        print(token_data)
        sys.exit(1)

    print("Login erfolgreich.")
    print("Token-Type:", token_data.get("token_type"))
    print("Expires in:", token_data.get("expires_in"))
    print()
    print("Bearer Token:")
    print(access_token)

    if refresh_token:
        print()
        print("Refresh Token wurde ebenfalls empfangen.")

    print()
    print("Finanzuebersicht:")
    overview = fetch_financial_overview(access_token, "MEINE")
    print(json.dumps(overview, ensure_ascii=False, indent=2))
    save_json("finanzdaten_meine.json", overview)
    print()
    print("Gespeichert: finanzdaten_meine.json")
