import pytest
import random
import requests
from requests.utils import unquote
import quopri
import re
import time

# Endpoints locales usados por el práctico
MAILHOG_API = "http://localhost:8025/api/v2/messages"
BASE_API = "http://localhost:5000"

# ------------------------------
# Utilidades para MailHog
# ------------------------------

def _mh_get_latest_body():
    """
    Devuelve el cuerpo (decodificado) del email más reciente en MailHog.
    Retorna None si aún no llegó nada.
    """
    resp = requests.get(MAILHOG_API)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("items"):
        return None
    body = data["items"][0]["Content"]["Body"]
    return unquote(quopri.decodestring(body).decode("utf-8", errors="replace"))

def _first_href(html_text):
    """Extrae el primer href de un HTML simple."""
    m = re.findall(r'<a\s+href=["\']([^"\']+)["\']', html_text or "", re.IGNORECASE)
    return m[0] if m else None

def _query_param(url, key):
    """Obtiene el valor de un parámetro ?key= desde una URL."""
    pat = re.compile(rf"(?:[?&]){re.escape(key)}=([^&#]+)")
    m = pat.search(url or "")
    return m.group(1) if m else None

# ------------------------------
# Setup: crear usuario + activar
# ------------------------------

@pytest.fixture(autouse=True)
def usuario_habilitado():
    """
    Crea un usuario aleatorio, obtiene el token de activación desde MailHog y
    deja el login listo para usarse en cada test.
    """
    n = random.randint(1000, 999_999)
    username = f"user{n}"
    email = f"{username}@test.com"
    password = "password"

    # Alta de usuario
    r = requests.post(
        f"{BASE_API}/users",
        data={
            "username": username,
            "password": password,
            "email": email,
            "first_name": "Name",
            "last_name": f"{username}son",
        },
    )
    assert r.status_code == 201, f"Alta falló: {r.status_code} {r.text}"

    # Esperar el correo y extraer token de activación
    token = None
    limite = time.time() + 12
    while time.time() < limite and not token:
        html = _mh_get_latest_body()
        if html:
            link = _first_href(html)
            token = _query_param(link, "token")
            if token:
                break
        time.sleep(0.5)

    assert token, "No se encontró token de activación en MailHog"

    # Activar cuenta
    a = requests.post(f"{BASE_API}/auth/set-password", json={"token": token, "newPassword": password})
    assert a.status_code in (200, 204), f"Activación falló: {a.status_code} {a.text}"

    # Devolver credenciales para login en los tests
    return [username, password]

def _jwt(usuario_habilitado):
    """Hace login y retorna el token JWT."""
    u, p = usuario_habilitado
    r = requests.post(f"{BASE_API}/auth/login", json={"username": u, "password": p})
    assert r.status_code == 200, f"Login falló: {r.status_code} {r.text}"
    return r.json()["token"]

# ------------------------------
# Pruebas de SQLi sobre /invoices
# ------------------------------

def test_login_basico(usuario_habilitado):
    """
    Sanity check: login devuelve un token utilizable.
    """
    u, p = usuario_habilitado
    r = requests.post(f"{BASE_API}/auth/login", json={"username": u, "password": p})
    assert r.status_code == 200
    assert r.json().get("token")

def test_no_bypass_con_or_1_igual_1(usuario_habilitado):
    """
    Verifica que un payload con 'OR 1=1' no incremente la cantidad de facturas
    visibles respecto a una consulta baseline válida.
    """
    token = _jwt(usuario_habilitado)
    headers = {"Authorization": f"Bearer {token}"}

    # Baseline: conteo legítimo (usuario nuevo => normalmente 0)
    base = requests.get(f"{BASE_API}/invoices", headers=headers, params={"status": "paid", "operator": "="})
    assert base.status_code == 200
    try:
        base_list = base.json()
        base_count = len(base_list) if isinstance(base_list, list) else 0
    except Exception:
        base_count = 0

    # Ataque: intenta abrir el WHERE con OR 1=1
    url = f"{BASE_API}/invoices?status=paid%27%20or%201%3D1%20--&operator=="
    resp = requests.get(url, headers=headers)
    assert resp.status_code == 200
    try:
        atk_list = resp.json()
        atk_count = len(atk_list) if isinstance(atk_list, list) else 0
    except Exception:
        atk_count = 0

    assert atk_count == base_count, (
        f"Posible SQLi: baseline={base_count} vs ataque={atk_count}. "
        f"Cuerpo: {resp.text[:400]}"
    )

def test_sin_union_exponiendo_datos(usuario_habilitado):
    """
    Intenta un UNION SELECT para inyectar filas ajenas. No deben aparecer
    usernames ni valores fuera del dominio esperado en el campo 'status'.
    """
    token = _jwt(usuario_habilitado)
    headers = {"Authorization": f"Bearer {token}"}

    url = (
        f"{BASE_API}/invoices?"
        "status=paid%27%20UNION%20SELECT%20id%2C%20id%2C%20%27100.00%27%3A%3Adecimal%2C%20CURRENT_DATE%2C%20username%20FROM%20users%20--"
        "&operator=="
    )
    r = requests.get(url, headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)

    # No deberían colarse usernames u otros valores raros en 'status'
    sospechosos = []
    for inv in data:
        s = inv.get("status")
        if s and s not in ("paid", "unpaid", "pending", "open", "closed", None):
            sospechosos.append(s)

    assert not sospechosos, f"Valores sospechosos en status (posible UNION leak): {sospechosos}"
    # Usuario recién creado => lo esperable es no tener facturas
    assert len(data) == 0, f"Usuario nuevo no debería tener facturas (recibidas: {len(data)})"
