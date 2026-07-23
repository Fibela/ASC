"""
Genera el token de enrolamiento SPECTER desde el secreto, leyéndolo de una variable
de entorno (evita problemas de comillas/escape en la shell).

Uso (PowerShell):
    $env:SPECTER_ENROLLMENT_SECRET = '<PEGA_AQUI_TU_SECRETO>'
    .\.venv\Scripts\python.exe gen_enrollment_token.py

Réplica exacta de asc_api.core.specter_security.generate_enrollment_token (ventana horaria).
"""
import hashlib
import hmac
import math
import os
import time

secret = os.environ.get("SPECTER_ENROLLMENT_SECRET", "")
if not secret:
    raise SystemExit("ERROR: define primero  $env:SPECTER_ENROLLMENT_SECRET = '<secreto>'")

window = math.floor(time.time() / 3600)
msg = f"SPECTER-ENROLL-PREMOSCORP:{window}"
token = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
print(token)
