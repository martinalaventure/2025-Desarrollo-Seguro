import os
import random
import time
import requests
import quopri
import re
from requests.utils import unquote

BASE_API = os.getenv("BASE_API", "http://localhost:5000")
MAILHOG_API = os.getenv("MAILHOG_API", "http://localhost:8025/api/v2/messages")


# =========================
# Helpers de activación
# =========================
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

def create_and_activate_user():
    """
    Crea un usuario de prueba, recupera el mail de activación desde MailHog,
    activa la cuenta y retorna un token JWT válido para usar en los endpoints protegidos.
    """
    i = random.randint(1000, 999_999)
    username = f"user{i}"
    email = f"{username}@test.com"
    password = "password"

    # Crear usuario
    r = requests.post(f"{BASE_API}/users", data={
        "username": username,
        "password": password,
        "email": email,
        "first_name": "Name",
        "last_name": f"{username}son",
    })
    r.raise_for_status()

    # Esperar el mail y extraer el token de activación
    deadline = time.time() + 12
    token = None
    while time.time() < deadline:
        mr = requests.get(MAILHOG_API)
        mr.raise_for_status()
        items = mr.json().get("items", [])
        for it in items:
            try:
                recipients = [rcpt.get("Mailbox", "") + "@" + rcpt.get("Domain", "") for rcpt in it.get("To", [])]
            except Exception:
                recipients = []
            if email.lower() not in {x.lower() for x in recipients}:
                continue
            html = _decode_body(it)
            link = _first_link(html)
            token = _q(link, "token")
            if token:
                break
        if token:
            break
        time.sleep(0.7)

    if not token:
        raise RuntimeError("No se encontró token de activación en MailHog")

    # Activar usuario
    act = requests.post(f"{BASE_API}/auth/set-password", json={"token": token, "newPassword": password})
    act.raise_for_status()

    # Login para obtener JWT
    lg = requests.post(f"{BASE_API}/auth/login", json={"username": username, "password": password})
    lg.raise_for_status()
    return lg.json().get("token")


# ============================================================
# PRUEBAS DE REGRESIÓN: Visualización de facturas sin SQLi
# ============================================================

def test_no_bypass_or_1_eq_1():
    """
    Test 1 — No bypass con 'OR 1=1':
    Verifica que un payload clásico de inyección (status="paid' OR 1=1 --")
    NO aumente la cantidad de resultados respecto a una consulta baseline válida.

    Criterio de éxito (mitigado):
    - Respuesta 200 y la cantidad de facturas devuelta por el ataque
      es IGUAL a la del baseline (para usuario nuevo suele ser 0).
    - Si fuera vulnerable, el ataque retornaría MÁS filas (leak).
    """
    token = create_and_activate_user()
    headers = {"Authorization": f"Bearer {token}"}

    # Baseline: cuántas facturas ve el usuario para un filtro legítimo
    baseline_params = {"status": "paid", "operator": "="}
    base = requests.get(f"{BASE_API}/invoices", headers=headers, params=baseline_params)
    assert base.status_code == 200, f"Baseline falló: {base.status_code} {base.text[:500]}"
    try:
        base_data = base.json()
        base_count = len(base_data) if isinstance(base_data, list) else 0
    except Exception:
        base_count = 0

    # Ataque: intenta bypasear el WHERE con OR 1=1
    attack_params = {"status": "paid' OR 1=1 --", "operator": "="}
    resp = requests.get(f"{BASE_API}/invoices", headers=headers, params=attack_params)
    assert resp.status_code == 200, f"Ataque falló: {resp.status_code} {resp.text[:500]}"
    try:
        atk_data = resp.json()
        atk_count = len(atk_data) if isinstance(atk_data, list) else 0
    except Exception:
        atk_count = 0

    assert atk_count == base_count, (
        f"Posible inyección SQL: baseline={base_count}, ataque={atk_count}.\n"
        f"Body ataque: {resp.text[:500]}"
    )


def test_no_union_leak_usernames():
    """
    Test 2 — Sin filtración por UNION:
    Intenta un UNION SELECT sobre el parámetro 'status' para forzar la mezcla
    de resultados de la tabla de usuarios (p.ej., 'username') con la de facturas.

    Criterio de éxito (mitigado):
    - Respuesta 200 con una lista y SIN valores sospechosos en 'status'
      (ni usernames, ni datos ajenos).
    - Para un usuario nuevo, además, no debería devolver filas.
    """
    token = create_and_activate_user()
    headers = {"Authorization": f"Bearer {token}"}

    payload = "paid' UNION SELECT id, id, '100.00'::decimal, CURRENT_DATE, username FROM users --"
    params = {"status": payload, "operator": "="}
    resp = requests.get(f"{BASE_API}/invoices", headers=headers, params=params)
    assert resp.status_code == 200, f"UNION request falló: {resp.status_code}"
    invoices = resp.json()
    assert isinstance(invoices, list), "Se esperaba lista JSON de facturas"

    # No deben aparecer valores “raros” en status (p.ej., usernames)
    sospechosos = []
    for inv in invoices:
        s = inv.get("status")
        if s and s not in ("paid", "unpaid", "pending", "open", "closed", None):
            sospechosos.append(s)

    assert len(sospechosos) == 0, f"UNION leak: valores sospechosos en status: {sospechosos}"
    # Usuario recién creado: lo esperable es 0 resultados
    assert len(invoices) == 0, f"Usuario nuevo no debería tener facturas, recibió {len(invoices)}"


def test_no_time_based_delay_pg_sleep():
    """
    Test 3 — Sin retardo por time-based SQLi:
    Intenta ejecutar una función de demora (pg_sleep(3)) usando un payload boolean-based.
    Si el servidor ejecuta la inyección, la respuesta demorará ~3s.

    Criterio de éxito (mitigado):
    - Respuesta 200 en MENOS de ~1.5s (umbral práctico),
      lo que indica que no se ejecutó pg_sleep(3).
    """
    token = create_and_activate_user()
    headers = {"Authorization": f"Bearer {token}"}

    payload = "paid' AND (SELECT pg_sleep(3)) IS NULL --"
    params = {"status": payload, "operator": "="}

    start = time.time()
    resp = requests.get(f"{BASE_API}/invoices", headers=headers, params=params)
    elapsed = time.time() - start

    assert resp.status_code == 200, f"Timing request falló: {resp.status_code}"
    assert elapsed < 1.5, f"Respuesta demasiado lenta ({elapsed:.2f}s): posible SQLi basada en tiempo"
