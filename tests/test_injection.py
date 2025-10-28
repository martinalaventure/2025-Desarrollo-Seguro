import pytest
import random
import requests
from requests.utils import unquote
import quopri
import re

"""
Estas pruebas se centran en verificar que los
endpoints relacionados con facturas están protegidos contra ataques de inyección SQL a
través de los parámetros de consulta.

Pruebas implementadas:
1. test_factura_status: Verifica la protección contra inyección SQL
   en el parámetro 'status' al listar facturas.
2. test_factura_operator: Verifica la protección contra inyección SQL
   en el parámetro 'operator' al listar facturas.
"""

# crear token, esto lo tomamos igual que en el archivo test_security.py
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
    i = random.randint(1000, 999999)
    username = f'user{i}'
    email = f'{username}@test.com'
    password = 'password'
    salida = requests.post("http://localhost:5000/users",
                           data={
                               "username": username,
                               "password": password,
                               "email": email,
                               "first_name": "Name",
                               "last_name": f'{username}son'
                           })
    # user created
    assert salida.status_code == 201

    mail = get_last_email_body()
    link = extract_links(mail)
    token = extract_query_params(link)

    # activate user
    response = requests.post("http://localhost:5000/auth/set-password", json={"token": token, "newPassword": password})
    

    return {username,password}

def test_factura_status(setup_create_user):
    """
    Test de regreción que verifica la protección contra inyección SQL a través del
    parámetro 'status' en el endpoint de listado de facturas.

    Esta prueba:
    1. Crea un usuario de prueba y obtiene un token de autenticación
    2. Intenta realizar una inyección SQL usando un valor malo en el parámetro 'status'
    3. Se va a verificar que la app:
       - Rechaza caracteres no permitidos en el parámetro status
       - Devuelve un código de error 400 (Bad Request)

    Args:
        setup_create_user: sería el usuario de prueba
    """
    # Logueamos al usuario para poder obtener el token
    credentials = setup_create_user
    login_response = requests.post("http://localhost:5000/auth/login",
                                 json={"username": credentials["username"],
                                      "password": credentials["password"]})
    assert login_response.status_code == 200
    auth_token = login_response.json()["token"]
    
    # Intento de la inyección sql a través de status
    headers = {"Authorization": f"Bearer {auth_token}"}
    status_malicioso = "paid' OR '1'='1"
    
    response = requests.get(
        f"http://localhost:5000/invoices?status={status_malicioso}",
        headers=headers
    )
    
    # Verificamos que la app rechace el valor del ststus
    assert response.status_code == 400, "Debería rechazar información maliciosa"


def test_factura_operator(setup_create_user):
    """
    Test de regresión que verifica la protección contra inyección SQL a través del
    parámetro 'operator' en el endpoint de listado de facturas.

    Esta prueba:
    1. Crea un usuario de prueba y obtiene un token de autenticación
    2. Intenta realizar una inyección SQL usando un valor malicioso en el parámetro 'operator'
    3. Se va a verificar que la app:
       - Solo acepta operadores válidos predefinidos
       - Devuelve un código de error 400 (Bad Request)

    Args:
        setup_create_user: sería el usuario de prueba
    """

    # Logueamos al usuario para poder obtener el token
    credentials = setup_create_user
    login_response = requests.post("http://localhost:5000/auth/login",
                                 json={"username": credentials["username"],
                                      "password": credentials["password"]})
    assert login_response.status_code == 200
    auth_token = login_response.json()["token"]
    
    # Intento de la inyección sql a través de operator
    headers = {"Authorization": f"Bearer {auth_token}"}
    operator_malicioso = "= OR 1=1; --"
    
    response = requests.get(
        f"http://localhost:5000/invoices?status=paid&operator={operator_malicioso}",
        headers=headers
    )
    
        # Verificamos que la app rechace el valor del operator
    assert response.status_code == 400, "Debería rechazar información maliciosa"
    
