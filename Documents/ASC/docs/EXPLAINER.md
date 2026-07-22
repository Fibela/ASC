# Explicación adaptativa de alertas — ASC (S102/S109/S110)

La ventaja competitiva de ASC: cada alerta se **explica y recomienda** en lenguaje adaptado al
perfil del cliente (hogar / pyme / enterprise), en vivo. **El módulo EXPLICA y RECOMIENDA;
nunca decide ni ejecuta** — la acción la toma el motor determinista o el analista.

## Motor PROPIO de PremosCorp (S110 — sin LLM externo)

Decisión (2026-07-22): **reemplazo total de Anthropic por un motor determinista propio.**
Razones:
- **Privacidad = venta:** tu telemetría de seguridad **NUNCA sale a un tercero**. Diferenciador
  real frente a productos que mandan los datos a un LLM externo.
- **Cero costo por uso** y **cero dependencia** (Anthropic requería créditos — nos frenó).
- **Cero alucinación:** es determinista; no inventa datos que la alerta no trae.

`asc_api/services/local_explainer.py` genera 3 secciones (**qué ocurrió · por qué importa · qué
se recomienda considerar**) a partir de los campos REALES de la alerta, usando una **base de
conocimiento MITRE ATT&CK** (activo propio, crece con el tiempo) y un mapa de acciones→lenguaje
por registro. Si un campo falta, se omite. Se emite palabra a palabra para conservar el efecto
de streaming en vivo.

## Arquitectura (seguridad y privacidad)

- El endpoint `POST /api/v1/alerts/{alert_id}/explain` (auth JWT, aislado por tenant) devuelve
  `text/event-stream` con eventos `meta` · `delta` · `done` · `error`.
- El frontend consume el SSE por `fetch` con el **JWT en el HEADER** (no en la URL).
- **No hay API key ni servicio externo** → no hay 503 por "no configurado"; el explainer
  **siempre responde**.
- El perfil (hogar/pyme/enterprise) se toma del **tenant en DB**, no de un selector del cliente.

## Frontend

- `src/lib/explainStream.ts` — consumidor SSE (`parseSSEChunk` puro + `streamExplanation`).
- `src/components/dashboard/ExplainPanel.tsx` — modal con streaming en vivo + badge de perfil.
- Botón **"Explicar"** por alerta en `/alerts`.

## Testing

- `backend/tests/test_s110_local_explainer.py` (8): 3 secciones, registros distintos por perfil,
  mapeo MITRE (conocido + genérico con código), **omisión de campos ausentes (nada inventado)**,
  guardrail (recomienda, nunca "ejecutamos"), acciones humanizadas, streaming reensambla.
- `backend/tests/test_s102_explainer.py` (10): guardrail de registros, contexto, auth,
  aislamiento de tenant, y el endpoint **real end-to-end** (motor propio, sin mock, 200 + stream).
- `frontend/src/__tests__/explain-stream.test.ts` — parser SSE (jest, para CI).

## Base de conocimiento MITRE (extensible)

Hoy cubre: T1110 (fuerza bruta), T1071 (C2), T1547 (persistencia), T1021 (movimiento lateral),
T1048 (exfiltración), T1003 (credential dumping) + fallback genérico. Ampliar `_TTP_KB` para
más técnicas es aditivo y no rompe nada.

## Roadmap (opcional, futuro)

Capa premium híbrida: un LLM (externo o self-hosted) podría *enriquecer* la prosa cuando el
cliente lo autorice explícitamente, cayendo siempre al motor propio. No implementado ni
requerido — el motor propio es la base completa.
