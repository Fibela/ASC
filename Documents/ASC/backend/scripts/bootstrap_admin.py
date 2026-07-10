#!/usr/bin/env python3
"""
Bootstrap del primer usuario administrador en ASC PremosCorp.

Uso:
  python scripts/bootstrap_admin.py

El script llama a POST /api/v1/auth/register, que solo funciona cuando la base
de datos NO tiene usuarios. El primer usuario siempre queda como rol "admin"
sin importar lo que se pase. Si ya existen usuarios devuelve 403 y termina.

Variables de entorno:
  ASC_URL   URL base del portal (default: https://asc.premoscorp.com)
"""

import os
import sys
import getpass
import urllib.request
import urllib.error
import json

ASC_URL = os.environ.get("ASC_URL", "https://asc.premoscorp.com").rstrip("/")
ENDPOINT = f"{ASC_URL}/api/v1/auth/register"


def main() -> None:
    print(f"\nASC PremosCorp — Bootstrap Admin")
    print(f"Endpoint: {ENDPOINT}\n")

    email     = input("Email del administrador: ").strip()
    full_name = input("Nombre completo: ").strip()
    password  = getpass.getpass("Contraseña (min. 12 caracteres, mayúsculas, números, símbolos): ")
    confirm   = getpass.getpass("Confirmar contraseña: ")

    if not email or not full_name or not password:
        print("\nError: todos los campos son obligatorios.")
        sys.exit(1)

    if password != confirm:
        print("\nError: las contraseñas no coinciden.")
        sys.exit(1)

    payload = json.dumps({
        "email":     email,
        "full_name": full_name,
        "password":  password,
        "role":      "admin",
    }).encode()

    req = urllib.request.Request(
        ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
            print(f"\nAdministrador creado:")
            print(f"  ID:    {body.get('id')}")
            print(f"  Email: {body.get('email')}")
            print(f"  Rol:   {body.get('role')}")
            print(f"\nYa puedes iniciar sesión en {ASC_URL}/login")
    except urllib.error.HTTPError as e:
        body = {}
        try:
            body = json.loads(e.read())
        except Exception:
            pass
        detail = body.get("detail", str(e))
        if e.code == 403:
            print(f"\nRegistro cerrado — ya existen usuarios en la base de datos.")
            print(f"Usa el panel de administración para gestionar usuarios.")
        elif e.code == 422:
            print(f"\nDatos inválidos: {detail}")
        else:
            print(f"\nError HTTP {e.code}: {detail}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"\nNo se pudo conectar con {ASC_URL}: {e.reason}")
        print("Verifica que el portal esté activo y accesible.")
        sys.exit(1)


if __name__ == "__main__":
    main()
