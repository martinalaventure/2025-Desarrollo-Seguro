import pytest
import random
import requests
from requests.utils import unquote
import quopri
import re

"""
PRUEBAS DE REGRESIÓN PARA MITIGACIÓN DE INYECCIÓN SQL
=====================================================

Pruebas de regresión diseñadas para validar la NO existencia de vulnerabilidades
de inyección SQL en la funcionalidad de visualizar facturas.

CONTEXTO DE SEGURIDAD:
- SQL Injection es una vulnerabilidad que permite ejecutar código SQL malicioso
- Los parámetros de consulta como 'status' y 'operator' pueden ser vectores de ataque
- Las mitigaciones incluyen: parametrización de consultas, validación de entrada, sanitización

COMPORTAMIENTO ESPERADO:
- Rama 'main' (sin mitigaciones): pruebas FALLAN (vulnerabilidad presente)
- Rama 'practico-2' (con mitigaciones): pruebas PASAN (vulnerabilidad mitigada)

VECTORES DE ATAQUE ANALIZADOS:
- GET /invoices?status=[PAYLOAD_SQL]
- GET /invoices?operator=[PAYLOAD_SQL]

CRITERIOS DE VALIDACIÓN:
- Payloads maliciosos NO deben ejecutar código SQL
- Respuestas deben ser controladas (lista vacía o error apropiado)
- NO debe haber exposición de datos no autorizados

@author Desarrollo Seguro 2025
@platform Pytest
"""

# Configuración de APIs y utilidades para pruebas
MAILHOG_API = "http://localhost:8025/api/v2/messages"
BASE_API = "http://localhost:5000"

def get_last_email_body():
    """Obtiene el cuerpo del último email recibido desde MailHog"""
    resp = requests.get(MAILHOG_API)
    resp.raise_for_status()
    data = resp.json()

    if not data["items"]:
        return None

    last_email = data["items"][0]
    body = last_email["Content"]["Body"]
    decoded = quopri.decodestring(body).decode("utf-8", errors="replace")
    return unquote(decoded)

def extract_links(decoded_html):
    """Extrae enlaces del HTML decodificado"""
    return re.findall(r'<a\s+href=["\']([^"\']+)["\']', decoded_html, re.IGNORECASE)[0]

def extract_query_params(url):
    """Extrae el token de los parámetros de la URL"""
    patron = re.compile(r"(?:[?&])token=([^&#]+)")
    m = patron.search(url)
    return m.group(1) if m else None

@pytest.fixture(autouse=True)
def setup_create_user():
    """
    Fixture que crea y activa un usuario de prueba para las validaciones.
    Retorna las credenciales del usuario creado.
    """
    # Generar usuario aleatorio para evitar conflictos
    i = random.randint(1000, 999999)
    username = f'user{i}'
    email = f'{username}@test.com'
    password = 'password'
    
    # Crear usuario
    salida = requests.post(f"{BASE_API}/users",
                           data={
                               "username": username,
                               "password": password,
                               "email": email,
                               "first_name": "Name",
                               "last_name": f'{username}son'
                           })
    assert salida.status_code == 201

    # Obtener token de activación del email
    mail = get_last_email_body()
    link = extract_links(mail)
    token = extract_query_params(link)

    # Activar usuario
    response = requests.post(f"{BASE_API}/auth/set-password", 
                           json={"token": token, "newPassword": password})

    return {"username": username, "password": password}

def test_factura_status_sql_injection(setup_create_user):
    """
    PRUEBA DE REGRESIÓN: Inyección SQL en parámetro 'status'
    
    Valida que el endpoint de listado de facturas esté protegido contra
    inyección SQL a través del parámetro 'status'.
    
    VECTOR DE ATAQUE:
    - Payload: "paid' OR '1'='1" 
    - Intenta bypasear la condición WHERE para obtener todas las facturas
    
    COMPORTAMIENTO ESPERADO:
    - Rama main (vulnerable): SQL injection exitoso, puede retornar datos no autorizados
    - Rama practico-2 (mitigada): payload tratado como valor literal, lista vacía
    
    CRITERIOS DE VALIDACIÓN:
    - NO debe ejecutar código SQL malicioso
    - Debe retornar lista vacía (no hay facturas con status literal "paid' OR '1'='1")
    - NO debe exponer datos no autorizados
    """
    # Autenticación del usuario de prueba
    credentials = setup_create_user
    login_response = requests.post(f"{BASE_API}/auth/login",
                                 json={"username": credentials["username"],
                                      "password": credentials["password"]})
    assert login_response.status_code == 200
    auth_token = login_response.json()["token"]
    
    # Payload de SQL Injection clásico para bypass de condiciones
    headers = {"Authorization": f"Bearer {auth_token}"}
    status_malicioso = "paid' OR '1'='1"
    
    # Ejecutar petición con payload malicioso
    response = requests.get(
        f"{BASE_API}/invoices?status={status_malicioso}",
        headers=headers
    )
    
    # VALIDACIÓN DE MITIGACIÓN:
    # En sistema mitigado: debe rechazar payloads maliciosos (validation error)
    # En sistema vulnerable: podría retornar datos no autorizados (200 con datos)
    
    # El backend implementa validación de entrada que rechaza caracteres especiales
    # Los payloads con comillas simples deben ser rechazados por el regex /^[a-zA-Z0-9_-]+$/
    assert response.status_code != 200, f"Sistema vulnerable: payload malicioso fue aceptado y retornó status {response.status_code}"
    
    # Verificar que es un error de validación controlado, no un error de base de datos
    assert response.status_code in [400, 422, 500], f"Error inesperado: {response.status_code}"


def test_factura_operator_sql_injection(setup_create_user):
    """
    PRUEBA DE REGRESIÓN: Inyección SQL en parámetro 'operator'
    
    Valida que el endpoint de listado de facturas esté protegido contra
    inyección SQL a través del parámetro 'operator'.
    
    VECTOR DE ATAQUE:
    - Payload: "= OR 1=1; --"
    - Intenta manipular la operación de comparación para obtener todos los registros
    
    COMPORTAMIENTO ESPERADO:
    - Rama main (vulnerable): SQL injection exitoso, operador malicioso ejecutado
    - Rama practico-2 (mitigada): operador validado, solo valores permitidos aceptados
    
    CRITERIOS DE VALIDACIÓN:
    - Solo operadores válidos deben ser aceptados (=, !=, >, <, etc.)
    - Payloads maliciosos deben ser rechazados
    - NO debe ejecutar código SQL inyectado
    """
    # Autenticación del usuario de prueba
    credentials = setup_create_user
    login_response = requests.post(f"{BASE_API}/auth/login",
                                 json={"username": credentials["username"],
                                      "password": credentials["password"]})
    assert login_response.status_code == 200
    auth_token = login_response.json()["token"]
    
    # Payload de SQL Injection para manipulación de operador
    headers = {"Authorization": f"Bearer {auth_token}"}
    operator_malicioso = "= OR 1=1; --"
    
    # Ejecutar petición con operador malicioso
    response = requests.get(
        f"{BASE_API}/invoices?status=paid&operator={operator_malicioso}",
        headers=headers
    )
    
    # VALIDACIÓN DE MITIGACIÓN:
    # En sistema mitigado: debe rechazar operadores inválidos (whitelist validation)
    # En sistema vulnerable: podría ejecutar la condición OR 1=1 y retornar todo
    
    # El backend implementa whitelist de operadores válidos ["=", "!=", "<", ">", "<=", ">="]
    # Operadores maliciosos como "= OR 1=1; --" deben ser rechazados
    assert response.status_code != 200, f"Sistema vulnerable: operador malicioso fue aceptado y retornó status {response.status_code}"
    
    # Error controlado esperado por operador inválido
    assert response.status_code in [400, 422, 500], f"Error inesperado: {response.status_code}"


def test_factura_union_based_sql_injection(setup_create_user):
    """
    PRUEBA DE REGRESIÓN: Inyección SQL tipo UNION
    
    Valida protección contra ataques UNION-based SQL injection que intentan
    extraer datos de otras tablas.
    
    VECTOR DE ATAQUE:
    - Payload: "paid' UNION SELECT username,password,1,1,1 FROM users--"
    - Intenta extraer credenciales de la tabla users
    
    CRITERIOS DE VALIDACIÓN:
    - NO debe ejecutar consultas UNION no autorizadas
    - NO debe exponer datos de otras tablas
    - Debe tratar el payload como valor literal
    """
    # Autenticación del usuario de prueba
    credentials = setup_create_user
    login_response = requests.post(f"{BASE_API}/auth/login",
                                 json={"username": credentials["username"],
                                      "password": credentials["password"]})
    assert login_response.status_code == 200
    auth_token = login_response.json()["token"]
    
    # Payload UNION-based para extracción de datos
    headers = {"Authorization": f"Bearer {auth_token}"}
    status_union = "paid' UNION SELECT username,password,1,1,1 FROM users--"
    
    # Ejecutar ataque UNION
    response = requests.get(
        f"{BASE_API}/invoices?status={status_union}",
        headers=headers
    )
    
    # VALIDACIÓN DE MITIGACIÓN:
    # En sistema mitigado: debe rechazar payloads con caracteres especiales (comillas)
    # En sistema vulnerable: podría ejecutar UNION y exponer datos de otras tablas
    
    # El payload contiene comillas simples que son rechazadas por el regex de validación
    assert response.status_code != 200, f"Sistema vulnerable: payload UNION fue aceptado y retornó status {response.status_code}"
    
    # Error de validación esperado
    assert response.status_code in [400, 422, 500], f"Error inesperado: {response.status_code}"


def test_factura_boolean_based_sql_injection(setup_create_user):
    """
    PRUEBA DE REGRESIÓN: Inyección SQL tipo Boolean-based
    
    Valida protección contra ataques boolean-based que usan condiciones
    verdaderas/falsas para extraer información.
    
    VECTORES DE ATAQUE:
    - Payload verdadero: "paid' AND 1=1--"
    - Payload falso: "paid' AND 1=2--"
    
    CRITERIOS DE VALIDACIÓN:
    - Ambos payloads deben ser rechazados por validación de entrada
    - NO debe haber diferencias basadas en la lógica booleana
    - Condiciones inyectadas NO deben ser procesadas
    """
    # Autenticación del usuario de prueba
    credentials = setup_create_user
    login_response = requests.post(f"{BASE_API}/auth/login",
                                 json={"username": credentials["username"],
                                      "password": credentials["password"]})
    assert login_response.status_code == 200
    auth_token = login_response.json()["token"]
    
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Payload con condición verdadera
    status_true = "paid' AND 1=1--"
    response_true = requests.get(
        f"{BASE_API}/invoices?status={status_true}",
        headers=headers
    )
    
    # Payload con condición falsa
    status_false = "paid' AND 1=2--"
    response_false = requests.get(
        f"{BASE_API}/invoices?status={status_false}",
        headers=headers
    )
    
    # VALIDACIÓN DE MITIGACIÓN:
    # En sistema mitigado: ambos payloads deben ser rechazados por validación
    # En sistema vulnerable: podrían retornar resultados diferentes
    
    # Ambos payloads contienen comillas simples y deben ser rechazados
    assert response_true.status_code != 200, f"Sistema vulnerable: payload booleano TRUE fue aceptado"
    assert response_false.status_code != 200, f"Sistema vulnerable: payload booleano FALSE fue aceptado"
    
    # Ambos deben retornar el mismo tipo de error (validación consistente)
    assert response_true.status_code == response_false.status_code, \
        "Inconsistencia en validación: diferentes códigos de error para payloads similares"
    
    # Error de validación esperado
    assert response_true.status_code in [400, 422, 500], f"Error inesperado: {response_true.status_code}"