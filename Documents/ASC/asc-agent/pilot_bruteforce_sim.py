"""
Simulador de ataque para el piloto S106 — dispara la regla 'Brute Force Authentication'.

Reusa el cliente SPECTER REAL (SprecterComm): misma identidad Ed25519, mismo registro,
misma firma. Envía 3 eventos de fallo de autenticación; el puente de detección (S106.1)
debe crear una alerta de correlación CON NOMBRE, además de las de anomalía.

NO es un mock: pega al backend real y firma de verdad. Requiere que el backend tenga
desplegado el puente S106 (commit d57512c o posterior).

Uso (Windows):
    cd asc-agent
    .venv\\Scripts\\activate
    $env:SPECTER_BACKEND_URL = "https://asc.premoscorp.com"
    # $env:SPECTER_ENROLLMENT_TOKEN = "<token>"   # solo si el server exige enrolamiento
    python pilot_bruteforce_sim.py
"""
from __future__ import annotations

import os
import sys
import time

from specter.communicator import SprecterComm


def main() -> None:
    backend = os.environ.get("SPECTER_BACKEND_URL", "https://asc.premoscorp.com")
    verify = os.environ.get("SPECTER_VERIFY_SSL", "true").lower() != "false"

    comm = SprecterComm(backend, verify_ssl=verify)
    print(f"[SIM] Backend: {backend}")

    if not comm.register():
        print("[SIM] FATAL: no se pudo registrar. Si el server exige enrolamiento, "
              "define SPECTER_ENROLLMENT_TOKEN. Abortando.")
        sys.exit(1)
    print(f"[SIM] Registrado. Agent ID: {comm.agent_id}")

    now = time.time()
    events = [
        {
            "event_type": "auth",
            "category": "authentication",   # requerido por la regla brute force
            "action": "login_failed",       # la regla busca 'fail' en action
            "severity": "info",
            "user": "administrator",
            "src_ip": "203.0.113.66",        # IP de documentación (RFC 5737)
            "host": comm.agent_id or "pilot-host",
            "ts": now + i * 0.01,
        }
        for i in range(3)
    ]

    result = comm.submit_events(events)
    print("[SIM] Respuesta del backend:", result)

    accepted = result.get("accepted", 0)
    alerts = result.get("alerts_created", 0)
    if accepted < 3:
        print(f"[SIM] ⚠️  Solo {accepted}/3 aceptados (revisa firma/replay/strict mode).")
    if alerts and alerts > 0:
        print(f"[SIM] ✅ {alerts} alerta(s) creada(s). Revisa el portal → Alerts: "
              "'Brute Force Authentication' (correlación) + posibles anomalías.")
    else:
        print("[SIM] ⚠️  0 alertas. Si el backend NO tiene el puente S106 desplegado, "
              "la telemetría se guarda pero no genera detección (comportamiento viejo).")


if __name__ == "__main__":
    main()
