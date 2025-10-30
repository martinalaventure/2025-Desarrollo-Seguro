import pytest
import random
import requests
from requests.utils import unquote
import quopri
import re

# crear token
MAILHOG_API = "http://localhost:8025/api/v2/messages"

def get_last_email_body():
    resp = requests.get(MAILHOG_API)
    resp.raise_for_status()
    data = resp.json()

    if not data["items"]:
        return None  # no emails received yet

    last_email = data["items"][0]
    body = last_email["Content"]["Body"]
    decoded = quopri.decodestring(body).decode("utf-8", errors="replace")
    return unquote(decoded)

def extract_links(decoded_html):
    return re.findall(r'<a\s+href=["\']([^"\']+)["\']', decoded_html, re.IGNORECASE)[0]

def extract_query_params(url):
    # regex: busca ?token= o &token= seguido de cualquier cosa hasta &, # o fin de string
    patron = re.compile(r"(?:[?&])token=([^&#]+)")
    m = patron.search(url)
    return m.group(1) if m else None

@pytest.fixture(autouse=True)
def setup_create_user():
    # random username
    i= random.randint(1000, 999999)
    username = f'user{i}'
    email = f'{username}@test.com'
    password = 'password'
    salida = requests.post("http://localhost:5000/users",
                        data={
                            "username": username, 
                            "password": password,
                            "email":email,
                            "first_name":"Name",
                            "last_name": f'{username}son'
                            })
    # user created
    assert salida.status_code == 201

    mail = get_last_email_body()
    link = extract_links(mail)
    token = extract_query_params(link)

    # activate user
    response = requests.post("http://localhost:5000/auth/set-password", json={"token": token, "newPassword": password})


    return [username,password]

def test_login(setup_create_user):
    username = setup_create_user[0]
    password = setup_create_user[1]

    response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    auth_token = response.json()["token"]
    assert auth_token
    
def get_token(setup_create_user):
    username = setup_create_user[0]
    password = setup_create_user[1]
    
    response = requests.post("http://localhost:5000/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["token"]


def test_listado_facturas_1_igual_1(setup_create_user):
    """
    Verificar que el filtro por `status` en /invoices NO sea vulnerable con `OR 1=1 --`. 
    Si el backend arma la consulta con concatenación de
    strings (vulnerable), el WHERE queda siempre verdadero y devuelve filas que no
    corresponden al usuario autenticado. En un backend bien mitigado, el payload
    se trata como valor literal y la respuesta es segura.
    """

    # 1) Obtener token de autenticación (el fixture ya creó y activó el usuario)
    token = get_token(setup_create_user)
    headers = {"Authorization": f"Bearer {token}"}

    # 2) Payload de ataque: fuerza un WHERE siempre-verdadero si hubiera concatenación
    #    status = "paid' or 1=1 --"
    #    operator = "="
    url = "http://localhost:5000/invoices?status=paid%27%20or%201=1%20--&operator=="

    # 3) Ejecutar la petición con el payload malicioso
    response = requests.get(url, headers=headers, timeout=5)

    # 4) Validaciones mínimas de contrato
    assert response.status_code == 200, f"Se esperaba 200, llegó {response.status_code}: {response.text[:300]}"
    invoices = response.json()
    assert isinstance(invoices, list), f"Se esperaba una lista JSON, llegó: {type(invoices)}"

    # 5) Condición clave de seguridad:
    #    En un sistema NO vulnerable, el usuario sin facturas debe recibir lista VACÍA.
    #    Si vinieran elementos, es indicio de que `OR 1=1` alteró el WHERE.
    assert len(invoices) == 0, "Posible SQL injection: llegaron facturas para un usuario sin registros."