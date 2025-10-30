import pytest
import random
import time
import requests
from requests.utils import unquote
import quopri
import re

"""
PRUEBAS DE REGRESIÓN PARA MITIGACIÓN DE INYECCIÓN SQL
=====================================================

Objetivo: que una rama vulnerable **FALLE** y una rama mitigada **PASE**.

Cambios clave:
- 500 ya NO es aceptable: si un payload causa 5xx, consideramos vulnerable.
- Si el backend decide ser "suave" y responde 200, exigimos **mismo conteo**
  que la consulta baseline (no-leak). Si el ataque devuelve más filas → FAIL.
"""

# --- Config ---
MAILHOG_API = "http://localhost:8025/api/v2/messages"
BASE_API = "http://localhost:5000"


# ---------- util comunes ----------
def safe_body(resp, limit=800):
    try:
        text = resp.text
    except Exception:
        return "<no-readable-body>"
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def assert_validation_error(resp):
    """
    Endurecido: solo 400/422 con JSON se aceptan como validación correcta.
    5xx => vulnerable (FAIL). 2xx con lista distinta se valida aparte.
    """
    assert resp.status_code in (400, 422), (
        f"Esperaba 400/422 (validación), llegó {resp.status_code}.\n{safe_body(resp)}"
    )
    ct = (resp.headers.get("content-type") or "").lower()
    assert "application/json" in ct, f"El error debe ser JSON, content-type={ct}"
    data = resp.json()
    assert isinstance(data, dict), f"Respuesta JSON debe ser objeto, fue: {type(data)}"
    assert ("error" in data) or ("message" in data), f"Falta mensaje de error en JSON: {data}"


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


def get_activation_token_for(to_email, timeout_s=10, poll_s=0.5):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = requests.get(MAILHOG_API)
        r.raise_for_status()
        for it in r.json().get("items", []):
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
        time.sleep(poll_s)
    return None


# --- Fixture de usuario de prueba ---
@pytest.fixture(autouse=True)
def setup_create_user():
    i = random.randint(1000, 999_999)
    username = f"user{i}"
    email = f"{username}@test.com"
    password = "password"

    # Crear usuario
    resp = requests.post(
        f"{BASE_API}/users",
        data={
            "username": username,
            "password": password,
            "email": email,
            "first_name": "Name",
            "last_name": f"{username}son",
        },
    )
    assert resp.status_code in (200, 201), f"Fallo creando usuario: {resp.status_code} {safe_body(resp)}"

    # Token de activación
    token = get_activation_token_for(email)
    assert token, "No se encontró token de activación en MailHog para el usuario creado"

    # Activar usuario
    act = requests.post(f"{BASE_API}/auth/set-password", json={"token": token, "newPassword": password})
    assert act.status_code in (200, 204), f"Fallo activando usuario: {act.status_code} {safe_body(act)}"

    return {"username": username, "password": password}


# --- Helpers de auth y conteo ---
def _auth_token(creds):
    r = requests.post(f"{BASE_API}/auth/login", json={"username": creds["username"], "password": creds["password"]})
    assert r.status_code == 200, f"Login falló: {r.status_code} {safe_body(r)}"
    data = r.json()
    assert "token" in data, f"Login sin token: {data}"
    return data["token"]


def _get_invoices(headers, params):
    r = requests.get(f"{BASE_API}/invoices", headers=headers, params=params)
    return r


def _assert_rejected_or_same_count(headers, baseline_params, attack_params):
    """
    Política:
    - Si ataque da 400/422 JSON => OK (validación).
    - Si ataque da 5xx => FAIL (vulnerable).
    - Si ataque da 200 => debe devolver **mismo conteo** que baseline (no-leak).
    """
    base = _get_invoices(headers, baseline_params)
    assert base.status_code == 200, f"Baseline debería ser 200: {base.status_code} {safe_body(base)}"
    try:
        base_data = base.json()
        base_count = len(base_data) if isinstance(base_data, list) else 0
    except Exception:
        base_count = 0  # mantenemos el test robusto aunque el contrato cambie

    atk = _get_invoices(headers, attack_params)

    # 5xx -> vulnerable
    assert atk.status_code < 500, f"500 recibido (vulnerable): {atk.status_code} {safe_body(atk)}"

    # 400/422 -> validación ok
    if atk.status_code in (400, 422):
        assert_validation_error(atk)
        return

    # 2xx -> comparar conteo
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


# --- Tests ---
def test_factura_status_sql_injection(setup_create_user):
    """
    Inyección SQL en 'status' (bypass clásico OR 1=1).
    Rama vulnerable: 500 o 200 con más filas -> FAIL.
    Rama mitigada: 400/422 o 200 con mismo conteo -> PASS.
    """
    auth = _auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {auth}"}

    baseline = {"status": "paid"}  # ajustá si tu dataset usa otro status
    attack   = {"status": "paid' OR '1'='1"}

    _assert_rejected_or_same_count(headers, baseline, attack)


def test_factura_operator_sql_injection(setup_create_user):
    """
    Inyección en 'operator' con cadena maliciosa.
    Rama vulnerable típica: rompe SQL (5xx) o filtra todo (más filas).
    """
    auth = _auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {auth}"}

    baseline = {"status": "paid", "operator": "="}
    attack   = {"status": "paid", "operator": "= OR 1=1; --"}

    _assert_rejected_or_same_count(headers, baseline, attack)


def test_factura_union_based_sql_injection(setup_create_user):
    """
    Inyección UNION para extraer de otra tabla.
    """
    auth = _auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {auth}"}

    baseline = {"status": "paid"}
    attack   = {"status": "paid' UNION SELECT username,password,1,1,1 FROM users--"}

    _assert_rejected_or_same_count(headers, baseline, attack)


def test_factura_boolean_based_sql_injection(setup_create_user):
    """
    Boolean-based (TRUE/FALSE). Ambos deben ser rechazados o dar mismo conteo.
    """
    auth = _auth_token(setup_create_user)
    headers = {"Authorization": f"Bearer {auth}"}

    baseline    = {"status": "paid"}
    attack_true = {"status": "paid' AND 1=1--"}
    attack_false= {"status": "paid' AND 1=2--"}

    _assert_rejected_or_same_count(headers, baseline, attack_true)
    _assert_rejected_or_same_count(headers, baseline, attack_false)
