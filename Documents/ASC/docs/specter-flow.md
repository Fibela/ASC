# Flujo ASC ↔ SPECTER — verificado contra código
**Session 101 · 2026-07-15.** Cada afirmación lleva su referencia `archivo:línea`. Lo que no se pudo verificar por lectura de código está separado al final en "Pendiente de prueba en runtime" — y no debe citarse como hecho hasta probarse.

---

## Vista general

```
ENDPOINT (host del cliente)                ASC API (Vercel asc-mono)              ANALISTA / MOTOR
┌─────────────────────────┐               ┌────────────────────────────┐
│ SPECTER agent (Python)  │               │                            │
│                         │  ① register   │ agents.py /register        │
│ identity.py (Ed25519)   ├──────────────►│ (enrollment token)         │
│                         │               │                            │
│ collectors/             │  ② events     │ agent_commander.py         │
│  network.py             ├──────────────►│  rate-limit → freshness →  │
│  processes.py           │   (firmados)  │  verify sig → novelty →    │
│                         │               │  AgentEvent (DB Supabase)  │
│                         │               │       │ ③ correlación      │
│                         │               │       ▼                    │
│                         │               │ correlator.py / sweep ────►│ Alert
│                         │               │                            │   │ ④ decisión
│                         │  ⑤ poll       │                            │   ▼
│ communicator.py         │◄──────────────┤ agents.py /commands        │ approval.py
│                         │   commands    │       ▲                    │   │
│ security.py (valida)    │               │       │                    │   ▼
│ executor/ (ejecuta)     │  ⑥ results    │ specter_bridge.dispatch ◄──┘ (o adapters
│                         ├──────────────►│ agents.py /results         │  o fallback)
└─────────────────────────┘               └────────────────────────────┘
```

El agente es **poll-based**: nunca recibe conexiones entrantes. Todo el tráfico lo inicia el endpoint hacia ASC.

---

## ① Enrollment

- El agente se auto-registra: `POST /api/v1/agents/register` (`agents.py:221`) presentando el enrollment token (expuesto a admins en `GET /agents/enrollment-token`, `agents.py:326`).
- Identidad del agente: par **Ed25519** generado localmente (`asc-agent/specter/identity.py`); la clave pública queda registrada en ASC, la privada nunca sale del endpoint.

## ② Telemetría (endpoint → ASC)

- Loop principal (`asc-agent/specter/agent.py:96-134`): collect → submit → poll → sleep. Intervalo **adaptativo por nivel de amenaza: 30s / 5s / 1s** (`agent.py:14`, ajustable por analista vía `PATCH /agents/{id}/threat`, `agents.py:711`).
- Colectores reales: `collectors/network.py` y `collectors/processes.py`. **Verificado: cero mocks/datos inventados en colectores y agente** (grep de mock/fake/random/dummy: 0 matches fuera de tests).
- Cada evento va **firmado** (`identity.sign_event`) y se envía en batch: `POST /agents/{id}/events` (`communicator.py:74-84`).
- Recepción (`agents.py:543` → `agent_commander.ingest_events`, `agent_commander.py:90`), en orden:
  1. **Rate limit** por agente (429 + audit log si se excede, `agents.py:557`).
  2. **Anti-replay**: timestamp fuera de ventana → rechazado.
  3. **Verificación de firma** contra la public key registrada; `signature_valid` se persiste por evento. `SPECTER_STRICT_SIGNATURE_MODE` emite evento de auditoría si hubo firmas inválidas (`agents.py:574`).
  4. **Detección de novedad**: `event_type` no visto en los últimos 500 eventos del agente → `is_anomaly=True`.
  5. Persistencia como `AgentEvent` en Supabase.

## ③ Correlación → Alertas

Dos caminos verificados:
- **Inline**: `POST /events/ingest/bulk` ejecuta `evaluate_correlation_rules` en el request (`events.py:77,98`) y crea alertas.
- **Barrido**: cron `correlation-sweep` cada 15 min (`cron.py:41` → `tasks/correlation_sweep._async_sweep` → `correlation_service.run_correlation_sweep`). ⚠️ Los endpoints cron **aún no están en producción** (nacen en S100, sin push).
- Enriquecimiento IOC: `correlator.match_iocs` (`correlator.py:67`) contra threat intel en DB.

## ④ Decisión (motor determinista o humano — nunca el LLM)

- Una alerta deriva en `approval.request_action` (`approval.py:108`): según política se ejecuta inmediato (`approval.py:203`) o queda pendiente de aprobación humana (`approve_action`, `approval.py:208`; `reject_action:345`; escalamiento por expiración: `escalate_expired:398`).
- La ejecución entra a `specter_bridge.dispatch` (`specter_bridge.py:472`), que rutea en este orden:
  1. **Acciones IAM** → `iam_service` (nivel base de datos/identidad).
  2. **Mapeo a comando SPECTER** (`map_specter_command:151`): targeted → `resolve_agent` por hostname/IP; broadcast → todos los agentes activos, batcheado y ordenado por proximidad (`_broadcast_batched:305`, `_sort_agents_by_proximity:271`).
  3. **Fallbacks etiquetados**: sin mapping, o sin agente activo → `neutralizer.execute_action` con `dispatch_mode=SIMULATION` y mensaje explícito `[simulation — …]` (`specter_bridge.py:505-540`). En el fallback, `block_ip`/`block_domain`/`disable_account` intentan primero **adaptadores reales** (PAN-OS/FortiGate/AD, `neutralizer.py:44-97,138-163`).

## ⑤ Poll de comandos (ASC → endpoint, iniciado por el endpoint)

- `GET /agents/{id}/commands` (`agents.py:591`; cliente: `communicator.poll_commands:91`).
- El agente valida antes de ejecutar (`security.py`): frescura del comando (ventana anti-replay, `:30`), validación estructural (`:48`), chequeo de inyección en parámetros (`:71`), HTTPS forzado (`:100`).
- **Canary ping**: ASC puede retar al agente con un nonce; el agente lo firma con su Ed25519 privada y ASC verifica contra la pública registrada (`security.py:85-96`) — prueba de vida criptográfica, no un "estoy vivo" de palabra.
- Ejecutores reales en el endpoint: `executor/` — `block_ip`, `unblock_ip`, `unblock_domain`, `isolate_endpoint`, `unisolate`, `kill_process`, `log_query`.

## ⑥ Resultado y auditoría

- `POST /agents/{id}/results` (`agents.py:619`; cliente: `communicator.report_result:123`).
- Trazabilidad por agente: `GET /agents/{id}/timeline` (`agents.py:743`) y `GET /agents/{id}/command-history` (`agents.py:783`).

## Defensa activa incorporada (verificado)

- **Honeypots**: `GET /agents/probe`, `/agents/dump`, `/agents/export` (`agents.py:364,409,454`) — endpoints trampa ocultos del schema OpenAPI que detectan reconocimiento contra la superficie del API.

---

## Deudas conocidas de este flujo (verificadas, por corregir)

1. **Simulaciones devuelven `success=True`** (`neutralizer.py:37-41` y similares). Están etiquetadas (`[SIMULATION]`, `simulation:True`, `dispatch_mode=SIMULATION`), pero el booleano `success` puede leerse como acción real en UI/reportes. Decisión pendiente: `success=False` o campo `simulated` de primera clase en la respuesta y en la UI.
2. Acciones que requieren agente vivo (`isolate_endpoint`, `kill_process`, `quarantine_file`, `remove_persistence`) **no tienen camino real sin SPECTER desplegado** en el endpoint objetivo — correcto por diseño, pero debe ser visible en la UI ("requiere agente").
3. CrowdStrike: **no existe** ningún adaptador. No citarlo como integración.

## Pendiente de prueba en runtime (no afirmable aún)

- Enrollment y telemetría de un agente real contra `asc.premoscorp.com` (nunca verificado end-to-end en esta sesión).
- El cron `correlation-sweep` corriendo en Vercel (requiere el push de S100 + `CRON_SECRET` en env).
- Latencias reales del poll adaptativo y del camino aprobación→dispatch→resultado.
- Carga: comportamiento del rate limiter con flota de agentes real.
