# Guía de despliegue de SPECTER — agente de telemetría de ASC

> Derivada del código real (`asc_api/api/v1/endpoints/agents.py`,
> `services/agent_commander.py`, `core/signing.py`), verificada 2026-07-21.
> SPECTER es la fuente de datos del cliente: un agente poll-based que registra,
> envía telemetría firmada y ejecuta comandos de neutralización.

## 0. Cómo encaja en el loop (S106.1)

```
SPECTER agent ──register──▶ ASC  (enrollment token, Ed25519 pubkey del agente)
     │
     ├──POST /events (firmado)──▶ ingesta ──▶ DETECCIÓN (correlación + anomalía)
     │                                              └──▶ Alert (scopeada al tenant)
     │                                                     └──▶ incidente / respuesta
     └──GET /commands (poll)◀── comandos de neutralización ◀── motor determinista / analista
```
El puente telemetría→alerta se cerró en S106.1: antes la telemetría se almacenaba sin
generar detección.

## 1. Prerrequisitos (servidor)

Variables de entorno en Vercel:
- `SPECTER_ENROLLMENT_SECRET` — **obligatoria**. Habilita la barrera de enrolamiento.
  Vacía = modo dev (sin barrera; NO usar en producción).
- `SPECTER_STRICT_SIGNATURE_MODE=true` — **recomendada en producción**. Rechaza eventos
  con firma Ed25519 inválida (sin ella, la firma es inerte).
- `SPECTER_SIGNING_PRIVATE_KEY` / `SPECTER_SIGNING_PUBLIC_KEY` — el backend firma los
  comandos que envía al agente; el agente verifica con la pública (`backend_pub_key`).
- `SPECTER_MAX_EVENTS_PER_BATCH` (default 200).

## 2. Generar el par de llaves del agente (Ed25519)

Cada agente genera su par en el primer arranque y **nunca** envía la privada:

```python
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
priv = Ed25519PrivateKey.generate()
priv_b64 = base64.b64encode(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()   # guardar local, seguro
pub_b64  = base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()        # se envía en register
```

## 3. Obtener el token de enrolamiento (admin)

```
GET /api/v1/agents/enrollment-token      (auth: admin JWT)
→ { "token": "<hmac>", ... }
```
El token es HMAC-SHA256(SPECTER_ENROLLMENT_SECRET, ventana) con rotación horaria. Nunca
se expone el secreto. Solo admin (least privilege).

## 4. Registrar el agente

```
POST /api/v1/agents/register
Header: X-Specter-Token: <token de enrolamiento>
Body:
{
  "hostname":        "WS-01",
  "os_type":         "windows",         // windows | linux | macos
  "os_version":      "10",
  "arch":            "x86_64",          // x86_64 | arm64
  "ip_address":      "10.0.0.5",
  "public_key":      "<pub_b64 Ed25519>",
  "specter_version": "1.0.0",
  "labels":          { "site": "hq" },
  "tenant_id":       "<uuid del tenant>"  // ata el agente (y sus alertas) al cliente
}
→ { "agent_id": "...", "poll_interval": 30, "threat_level": "normal", "backend_pub_key": "..." }
```
Idempotente por `hostname` (re-registro actualiza). Guardar `agent_id` y `backend_pub_key`.

## 5. Enviar telemetría FIRMADA

```
POST /api/v1/agents/{agent_id}/events
Header: X-Specter-ID: <agent_id>
Body: { "events": [ <evento firmado>, ... ] }   // máx 200
→ { "accepted": N, "rejected": M, "alerts_created": K, "ts": "..." }
```
Cada evento se firma con la privada del agente sobre su forma canónica (sin el campo
`signature`), con el mismo esquema que `core/signing.sign_command`. El servidor verifica
contra la pública almacenada; en modo estricto, firma inválida = rechazo. `ts` debe estar
dentro de ±120 s (anti-replay).

### Esquema de evento recomendado (para que dispare DETECCIÓN)

`normalize_event` mapea a campos ECS; las reglas de correlación leen `category`, `action`,
`process`, `dst_port`, etc. Para que la telemetría genere alertas útiles, incluir:

```json
{
  "event_type": "auth",              // requerido
  "severity":   "info",              // info|low|medium|high|critical (high/critical → alerta directa)
  "category":   "authentication",    // authentication|registry|network|process|file...
  "action":     "login_failed",      // texto; las reglas buscan subcadenas (p.ej. "fail")
  "host":       "WS-01",
  "user":       "jdoe",
  "process":    "lsass.exe",
  "dst_port":   445,
  "src_ip":     "10.0.0.9",
  "ts":         1737500000.0,
  "signature":  "<firma Ed25519 base64>"
}
```
Reglas activas hoy: fuerza bruta (≥3 auth fail), persistencia en registro, credential
dumping (lsass/mimikatz), lateral movement (SMB 445/139), exfiltración. Además, cualquier
evento con `is_anomaly` (tipo no visto antes para ese agente) o `severity` high/critical
genera alerta.

## 6. Poll de comandos y reporte de resultado

```
GET  /api/v1/agents/{agent_id}/commands   Header: X-Specter-ID   → comandos pendientes (firmados por el backend)
POST /api/v1/agents/{agent_id}/results    Header: X-Specter-ID   Body: { command_id, status, result, error }
```
Intervalo de poll adaptativo por nivel de amenaza: normal 30 s, elevated 5 s, critical 1 s.

## 7. Verificación del despliegue (evidencia)

- Registro devuelve `agent_id`.
- POST de telemetría firmada devuelve `accepted > 0` y, si aplica, `alerts_created > 0`.
- Las alertas aparecen scopeadas al `tenant_id` del agente (aisladas de otros tenants).
- Prueba automatizada del loop: `backend/tests/test_s106_specter_loop.py` (5 tests) —
  telemetría firmada → correlación/anomalía → alerta tenant-scopeada, y honestidad del
  lado de respuesta (sin adaptador, `block_ip` no finge éxito).

## 8. Notas de seguridad

- La privada del agente nunca sale del host. El servidor solo guarda la pública.
- `SPECTER_STRICT_SIGNATURE_MODE=true` es lo que hace cumplir la firma; sin ella, un
  atacante que conozca el `agent_id` podría inyectar telemetría (corregido en S103.5).
- El token de enrolamiento rota cada hora y es admin-only.
- Acciones de respuesta a nivel host requieren el agente vivo; sin él, ASC reporta la
  acción como *simulada* honestamente (nunca como ejecutada).
