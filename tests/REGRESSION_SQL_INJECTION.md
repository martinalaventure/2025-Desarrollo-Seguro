# Pruebas de regresión — Inyección SQL (visualizar facturas)

Documento en español que describe la intención, cómo ejecutar y cómo interpretar
las pruebas de regresión para detectar inyección SQL en el endpoint `/invoices`.

Resumen
-------
- Objetivo: validar que la funcionalidad de listar facturas no sea vulnerable a
  inyección SQL por los parámetros `status` y `operator`.
- Framework: Pytest (tests en `tests/`).
- Requisitos: backend en `http://localhost:5000`, MailHog corriendo en `http://localhost:8025`.

Archivos relevantes
-------------------
- `tests/test_invoices_sql_injection.py` — suite de regresión principal (comparación
  baseline vs ataque, detección de 500 con indicios de SQL).
- `tests/test_user_supplied_injections.py` — pruebas basadas en ejemplos del equipo
  (OR 1=1, UNION, time-based). Contiene helper para crear/activar/login de usuario
  usando MailHog.

Variables de entorno (opcionales)
--------------------------------
- `BASE_API` — URL base de la API (por defecto `http://localhost:5000`).
- `MAILHOG_API` — URL de la API de MailHog (por defecto
  `http://localhost:8025/api/v2/messages`).
- `STRICT_HTTP` — si se establece a `1`, cualquier `5xx` hará fallar la prueba;
  de lo contrario los `500` que contengan mensajes "seguros" (p. ej. `invalid
  operator`) pueden aceptarse.

Requisitos previos
------------------
1. Backend ejecutándose en `BASE_API` (ver `docker-compose.yaml` si usas Docker).
2. MailHog ejecutándose para recibir correos de activación.
3. Entorno Python con `pytest` y `requests` disponible (se recomienda usar el
   virtualenv del proyecto `.venv`).

Cómo ejecutar las pruebas (PowerShell)
-------------------------------------
1) Activar virtualenv (si existe):

```powershell
.\.venv\Scripts\Activate.ps1
```

2) Ejecutar la suite completa de inyección (rápido):

```powershell
# Ejecuta todas las pruebas relacionadas
python -m pytest tests/test_invoices_sql_injection.py -q
python -m pytest tests/test_user_supplied_injections.py -q
```

3) Ejecutar una prueba específica (ejemplo):

```powershell
python -m pytest tests/test_user_supplied_injections.py::test_invoices_status_filter -q
```

Interpretación de resultados
----------------------------
- OK / PASA: la prueba no detectó indicios de inyección en la instancia probada.
  Puede deberse a que:
  - El backend tiene mitigaciones en vigor (validación, parametrización).
  - Estás probando una imagen/instancia diferente a la que crees (rebuild necesario).
  - La base de datos no contiene datos que permitan demostrar la fuga (usa el
    test "víctima" si se necesita mayor certeza).
- FAIL: la prueba encontró evidencia de inyección o exposición. Tipos habituales:
  - `500` con cuerpo que contiene `syntax error`, `select `, `username`, `password`,
    o un stacktrace — indica que el payload llegó a la BD y el error fue expuesto.
  - Conteo de filas mayor en la petición de ataque vs baseline — indica fuga.
  - Tiempo de respuesta significativamente alto en test de timing (pg_sleep).

Qué revisar si la prueba falla
------------------------------
1. Inspeccionar los logs del backend (Docker):

```powershell
docker-compose logs --tail=200 backend
```

2. Hacer una petición manual para ver el cuerpo completo y confirmar la exposición:

```powershell
# obtener token de un usuario (ver tests) o reutilizar uno válido
curl -i -G "http://localhost:5000/invoices" --data-urlencode "status=paid' OR 1=1 --" --data-urlencode "operator==" -H "Authorization: Bearer <TOKEN>"
```

3. Si el cuerpo contiene la consulta SQL o un stacktrace, el backend está expuesto —
   hay que parchearlo (validación + parametrización + ocultar mensajes de BD).

Recomendaciones para corregir la aplicación (resumen)
----------------------------------------------------
- Validar/whitelistear `operator` y `status` antes de construir la consulta.
- Usar consultas parametrizadas / la API de Knex (p. ej. `andWhere('status', operator, status)`) en lugar de concatenar.
- Capturar errores de BD y devolver mensajes genéricos al cliente; loggear detalles internamente.
- Añadir tests "víctima" que creen datos controlados para detectar fugas incluso con 500 genéricos.

Pruebas adicionales opcionales
------------------------------
- Test "víctima": crear un usuario con un valor único en una factura, ejecutar
  payload UNION y verificar que la cadena única no aparece en la respuesta.
- Test de fuzzing automático sobre parámetros `status` y `operator` con inputs
  comunes de SQLi.

Contacto y pasos siguientes
---------------------------
Si querés, puedo:
- Añadir el test "víctima" a la suite.
- Preparar un parche seguro para `src/services/invoiceService.ts` (validación +
  parametrización + manejo seguro de errores) y probarlo localmente.
- Ayudarte a reconstruir el contenedor y ejecutar las pruebas en la rama que
  indiques.

Indica qué prefieres y lo implemento.
