# Explicación adaptativa de alertas — ASC (S102/S109)

La ventaja competitiva de ASC: cada alerta se **explica y recomienda** en lenguaje adaptado al
perfil del cliente (hogar / pyme / enterprise), en vivo, token a token. **El módulo EXPLICA y
RECOMIENDA; nunca decide ni ejecuta** — la acción la toma el motor determinista o el analista.

## Arquitectura (seguridad primero)

- **La `ANTHROPIC_API_KEY` vive SOLO en el backend** (env de Vercel). Nunca viaja al frontend
  ni aparece en el repo. Auditado: cero referencias a la key en `frontend/src` (solo comentarios).
- El frontend consume un stream **SSE** del backend con el **JWT del usuario en el HEADER**
  (`Authorization: Bearer …`), no en la URL — más seguro que EventSource.
- El perfil (hogar/pyme/enterprise) se toma del **tenant en DB**, no de un selector del cliente.

## Backend (ya existía, 100% cubierto — S102/S104.2)

`POST /api/v1/alerts/{alert_id}/explain` → `text/event-stream` con eventos:
`meta` (alert_id, profile) · `delta` (text) · `done` · `error`. Devuelve **503** si falta la
`ANTHROPIC_API_KEY`. Aislado por tenant (la alerta debe ser del tenant del usuario).

## Frontend (S109 — nuevo)

- `src/lib/explainStream.ts` — consumidor SSE por `fetch` (POST + JWT en header) + parser puro
  `parseSSEChunk` (testeado: `src/__tests__/explain-stream.test.ts`).
- `src/components/dashboard/ExplainPanel.tsx` — modal que hace streaming del texto en vivo, con
  badge del perfil y la nota honesta del guardrail.
- Botón **"Explicar"** por alerta en `/alerts` → abre el panel.

## Activación (acción del fundador)

1. **Poner la key en Vercel:** proyecto `asc-mono` → Settings → Environment Variables →
   `ANTHROPIC_API_KEY = sk-ant-…` (Production). *(No la pegues en el chat.)*
2. *(Opcional)* `ANTHROPIC_MODEL` (default `claude-fable-5`), `EXPLAINER_MAX_TOKENS` (1024),
   `EXPLAINER_TIMEOUT_SECONDS` (25).
3. **Redeploy** (o el próximo push). Sin la key, el panel muestra "explainer no configurado"
   (503) — degradación honesta, no crash.

## Verificación

- Sin key → botón Explicar muestra el 503 honesto.
- Con key → el texto aparece en vivo, en el registro del perfil del tenant.
- Nunca se expone la key: el frontend solo ve el texto ya generado.
