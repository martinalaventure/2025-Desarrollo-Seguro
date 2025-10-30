# tests/test_invoices_sql_injection.py
import os
import pytest
import random
import time
import requests
import quopri
import re
from requests.utils import unquote

# ================== Config ==================
BASE_API    = os.getenv("BASE_API", "http://localhost:5000")
MAILHOG_API = os.getenv("MAILHOG_API", "http://localhost:8025/api/v2/messages")

API_TIMEOUT_S       = float(os.getenv("API_TIMEOUT_S", "5.0"))
API_READY_TIMEOUT_S = float(os.getenv("API_READY_TIMEOUT_S", "40"))
API_RETRY_DELAY_S   = float(os.getenv("API_RETRY_DELAY_S", "0.7"))
API_RETRIES         = int(os.getenv("API_RETRIES", "4"))

MAILHOG_TIMEOUT_S   = float(os.getenv("MAILHOG_TIMEOUT_S", "8.0"))
MAILHOG_RETRIES     = int(os.getenv("MAILHOG_RETRIES", "5"))
MAILHOG_DELAY_S     = float(os.getenv("MAILHOG_DELAY_S", "0.7"))

# Si STRICT_HTTP=1, NO se aceptan 500 “seguros”: sólo 400/422 o 200=baseline.
STRICT_HTTP = os.getenv("STRICT_HTTP", "0") == "1"

# Mensajes de error típicos “controlados” que tu backend puede devolver con 500
SAFE_500_MESSAGES = [
    "invalid operator",
    "invalid status format",
    "invalid status",
    "invalid parameter",
    "validation failed",
]

# Indicadores peligrosos de 500 por motor SQL o stack
DANGEROUS_MARKERS = [
    "sql", "syntax error", "traceback", "stack",
    "select ", "insert ", "update ", "delete ",
    "sqlite", "mysql", "postgres", "near", "ORA-", "psycopg", "Sequelize"
]

# ================== Helpers genéricos ==================
def safe_body(resp, limit=800):
    try:
        t = resp.text
    except Exception:
        return "<no-readable-body>"
    return t if len(t) <= limit else t[:limit] + "...<truncated>"

def request_with_retry(method, url, **kwargs):
    attempts = API_RETRIES
    for i in range(1, attempts + 1):
        try:
            return requests.request(method, url, timeout=API_TIMEOUT_S, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            if i == attempts:
                raise
            time.sleep(API_RETRY_DELAY_S)

def wait_for_api(base_url: str, timeout_s: float = API_READY_TIMEOUT_S):
    deadline = time.time() + timeout_s
    probe_paths = ["/health", "/status", "/_health", "/_status", "/"]
    last_err = None
    while time.time() < deadline:
        for p in probe_paths:
            try:
                r = requests.get(f"{base_url}{p}", timeout=API_TIMEOUT_S)
                # Cualquier HTTP (2xx–5xx) indica proceso vivo.
                return
            except requests.exceptions.RequestException as e:
                last_err = e
                time.sleep(API_RETRY_DELAY_S)
    raise RuntimeError(f"API no responde en {timeout_s}s en {base_url}. Último error: {last_err}")

def _decode_body(item):
    body = item["Content"]["Body"]
    decoded = quopri.decodestring(body).decode("utf-8", errors="replace")
    return unquote(decoded)

def _first_link(html):
    m = re.search(r'<a\s+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    return m.group(1) if m else None

def _q(url, name):
    m = re.search(rf"(?:[?&]){re.escape(name)}=([^&#]+)", url or "")
    return m.group(1) if m else None

def get_activation_token_for(to_email, timeout_s=12):
    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        for _ in range(MAILHOG_RETRIES):
            try:
                r = requests.get(MAILHOG_API, timeout=MAILHOG_TIMEOUT_S)
                r.raise_for_status()
                data = r.json()
                for it in data.get("items", []):
                    try:
                        recipients = [rcpt.get("Mailbox","")+"@"+rcpt.get("Domain","") for rcpt in it.get("To",[])]
                    except Exception:
                        recipients = []
                    if to_email.lower() not in {x.lower() for x in recipients}:
                        continue
                    html = _decode_body(it)
                    link = _first_link(html)
                    tok = _q(link, "token")
                    if tok:
                        return tok
            except requests.exceptions.RequestException as e:
                last_err = e
                time.sleep(MAILHOG_DELAY_S)
        time.sleep(MAILHOG_DELAY_S)
    raise RuntimeError(f"MailHog no entregó token para {to_email}. Último error: {last_err}")

def assert_validation_error(resp):
    assert resp.status_code in (400, 422), (
        f"Esperaba 400/422 (validación), llegó {resp.status_code}.\n{safe_body(resp)}"
    )
    ct = (resp.headers.get("content-type") or "").lower()
    assert "application/json" in ct, f"El error debe ser JSON, content-type={ct}"
    data = resp.json()
    assert isinstance(data, dict), f"Respuesta JSON debe ser objeto, fue: {type(data)}"
    assert ("error" in data) or ("message" in data), f"Falta mensaje de error en JSON: {data}"

def is_safe_500(resp):
    """Acepta 500 sólo si es un error controlado (validación), no del motor SQL."""
    if resp.status_code != 500:
        return False
    ct = (resp.headers.get("content-type") or "").lower()
    if "application/json" not in ct:
        return False
    try:
        data = resp.json()
    except Exception:
        return False
    msg = str(data.get("message") or data.get("error") or "").lower()
    if not msg:
        return False
    body_low = (resp.text or "").lower()
    if any(m in body_low for m in DANGEROUS_MARKERS):
        return False
    return any(s in msg for s in SAFE_500_MESSAGES)

# ================== Fixtures ==================
@pytest.fixture(autouse=True, scope="session")
def _wait_backend_once():
    wait_for_api(BASE_API)

@pytest.fixture(autouse=True)
def setup_create_user():
    i = random.randint(1000, 999_999)
    username = f"user{i}"
    email = f"{username}@test.com"
    password = "password"

    # Crear usuario
    resp = request_with_retry(
        "POST", f"{BASE_API}/users",
        data={
            "username": username,
            "password": password,
            "email": email,
            "first_name": "Name",
            "last_name": f"{username}son",
        },
    )
    assert resp.status_code in (200, 201), f"Fallo creando usuario: {resp.status_code} {safe_body(resp)}"

    token = get_activation_token_for(email)

    act = request_with_retry("POST", f"{BASE_API}/auth/set-password",
                             json={"token": token, "newPassword": password})
    assert act.status_code in (200, 204), f"Fallo activando usuario: {act.status_code} {safe_body(act)}"

    return {"username": username, "password": password}

# ================== Auth & core asserts ==================
def _auth_token(creds):
    r = request_with_retry("POST", f"{BASE_API}/auth/login",
                           json={"username": creds["username"], "password": creds["password"]})
    assert r.status_code == 200, f"Login falló: {r.status_code} {safe_body(r)}"
    data = r.json()
    assert "token" in data, f"Login sin token: {data}"
    return data["token"]

def _assert_rejected_or_same_count(headers, baseline_params, attack_params):
    base = request_with_retry("GET", f"{BASE_API}/invoices", headers=headers, params=baseline_params)
    assert base.status_code == 200, f"Baseline debería ser 200: {base.status_code} {safe_body(base)}"
    try:
        base_data = base.json()
        base_count = len(base_data) if isinstance(base_data, list) else 0
    except Exception:
        base_count = 0  # robusto ante cambios de contrato

    atk = request_with_retry("GET", f"{BASE_API}/invoices", headers=headers, params=attack_params)

    # 5xx -> vulnerable salvo 500 “seguro” (validación propia) y STRICT_HTTP apagado
    if atk.status_code >= 500:
        if STRICT_HTTP:
            pytest.fail(f"500 recibido (no permitido en STRICT_HTTP): {atk.status_code} {safe_body(atk)}")
        assert is_safe_500(atk), f"500 recibido (vulnerable): {atk.status_code} {safe_body(atk)}"
        return  # lo consideramos mitigación válida

    # 400/422 -> validación correcta
    if atk.status_code in (400, 422):
        assert_validation_error(atk)
        return

    # 2xx -> comparar conteo (no-leak)
    assert atk.status_code == 200, f"Respuesta inesperada al ataque: {atk.status_code} {safe_body(atk)}"
    try:
        atk_data = atk.json()
        atk_count = len(atk_data) if isinstance(atk_data, list) else 0
    except Exception:
        atk_count = 0
    assert atk_count == base_count, (
        f"Leak por inyección: baseline={base_count}, ataque={atk_count}.\n"
        f"Ataque params={attack_params}\n"
        f"Body ataque: {safe_body(atk)}"
    )

# ================== Tests ==================
def test_factura_status_sql_injection(setup_create_user):
    auth = _auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {auth}"}
    baseline = {"status": "paid"}            # ajusta si tu semilla usa otro estado
    attack   = {"status": "paid' OR '1'='1"}
    _assert_rejected_or_same_count(headers, baseline, attack)

def test_factura_operator_sql_injection(setup_create_user):
    auth = _auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {auth}"}
    baseline = {"status": "paid", "operator": "="}
    attack   = {"status": "paid", "operator": "= OR 1=1; --"}
    _assert_rejected_or_same_count(headers, baseline, attack)

def test_factura_union_based_sql_injection(setup_create_user):
    auth = _auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {auth}"}
    baseline = {"status": "paid"}
    attack   = {"status": "paid' UNION SELECT username,password,1,1,1 FROM users--"}
    _assert_rejected_or_same_count(headers, baseline, attack)

def test_factura_boolean_based_sql_injection(setup_create_user):
    auth = _auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {auth}"}
    baseline    = {"status": "paid"}
    attack_true = {"status": "paid' AND 1=1--"}
    attack_false= {"status": "paid' AND 1=2--"}
    _assert_rejected_or_same_count(headers, baseline, attack_true)
    _assert_rejected_or_same_count(headers, baseline, attack_false)
