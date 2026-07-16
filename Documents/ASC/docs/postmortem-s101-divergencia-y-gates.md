# Postmortem S101 — 2026-07-15
## Tres fallas estructurales, su causa común, y las reglas para no repetirlas

Todo lo afirmado aquí fue verificado con salida de comandos en la Session 101 (evidencia por hallazgo en `AUDIT_LOG.md` § Session 101). Nada proviene de leer documentación.

---

## Falla 1 — Copia duplicada de `asc_api` mantenida a mano

**Qué pasó.** El API vive dos veces: `backend/asc_api` (donde se desarrolla) y `frontend/asc_api` (lo que Vercel `asc-mono` sirve en producción vía `frontend/api/index.py`). No existía ningún mecanismo de sincronización — ni build step, ni script, ni test. Cada cambio dependía de que un humano recordara copiar.

**Impacto real (no hipotético).** El fix CORS de S99 (`main.py:103`) y los 5 endpoints de cron de S100 se aplicaron solo a `backend/asc_api`. De haberse pusheado, producción habría quedado con el bug CORS intacto y 5 crons de `vercel.json` apuntando a rutas 404. La divergencia acumulada era de 7 archivos: `cron.py` y `seed_correlation.py` ausentes; `agents.py`, `auth_sso.py`, `router.py`, `config.py`, `main.py` con contenido distinto. Es el mismo patrón del incidente I-2 (frontend apuntando a un backend eliminado): dos representaciones del sistema que nadie obliga a coincidir.

**Corrección aplicada.** `backend/asc_api` es la única fuente. `frontend/asc_api` es un espejo generado que nunca se edita a mano. Tres capas lo imponen: `scripts/sync-asc-api.mjs` (propagación, modo `--check`), `backend/tests/test_asc_api_sync.py` (rompe la suite si diverge un byte — validado primero en rojo contra la divergencia real, luego en verde tras el sync), y `frontend/scripts/prebuild-sync.cjs` (re-sync en cada build de Vercel donde el monorepo sea visible).

**Regla.** Si un artefacto existe en dos lugares, o se genera uno desde el otro con verificación automática, o uno de los dos sobra. "Acordarse de copiar" no es un mecanismo.

---

## Falla 2 — CI que nunca existió

**Qué pasó.** Los 5 workflows (`ci.yml`, `deploy.yml`, `p49-security-gates.yml`, `p50-e2e.yml`, `security-audit.yml`) viven en `Documents/ASC/.github/workflows/`. GitHub solo ejecuta workflows desde `.github/` en el **root** del repositorio — y el root real (local y `origin/master`) contiene únicamente `Documents` y `LEEME` ("My Project": el repo se inicializó en la carpeta equivocada). **Ningún workflow se ha ejecutado jamás.**

**Impacto real.** Todo lo que la documentación atribuye al "CI gate" — bloquear código roto antes del deploy, security gates, E2E — nunca ocurrió. La suite verde solo se ha corrido localmente. Vercel despliega desde git sin ningún gate delante. Peor: `deploy.yml` describía en sus comentarios un sistema de protección que el propio archivo no podía ejecutar, y los docs lo citaban como activo.

**Corrección aplicada.** Documentada y en cola de decisión (afecta el Root Directory del proyecto Vercel): mover el contenido de `Documents/ASC/` al root del repo (opción correcta) o crear workflows-wrapper en el root real (parche). Hasta entonces, el gate de integridad corre en la suite local de pytest, que es el único gate que existe de verdad.

**Regla.** Un gate está activo cuando se ha visto correr (una ejecución en la pestaña Actions, un deploy bloqueado), no cuando su archivo existe. Declarar protecciones por existencia de artefacto es cómo se acumularon 13,181 líneas de documentación falsa.

---

## Falla 3 — Line endings sin gobernar

**Qué pasó.** Sin `.gitattributes`, algún editor de Windows convirtió 47 archivos a CRLF. `git status` reportaba 47 modificados; el diff real de contenido (`git diff --ignore-cr-at-eol`) era **vacío**.

**Impacto real.** Ruido que enmascara señal: con 47 archivos "modificados" permanentes, un cambio real accidental pasaría desapercibido dentro del montón. Además bloqueó el diagnóstico inicial de esta sesión hasta separarlo.

**Corrección aplicada.** `.gitattributes` en el root del repo (LF para código, CRLF para `.ps1`, binarios marcados) + renormalización en el commit de esta sesión.

**Regla.** Ante un diff sospechosamente grande y parejo (N insertions = N deletions), correr `git diff --ignore-cr-at-eol --stat` antes de leer una sola línea.

---

## La causa común

Las tres fallas son la misma falla: **declarar estado por construcción en lugar de por observación.** "El archivo del workflow existe" ≠ el workflow corre. "Copié el API al frontend" ≠ las copias coinciden. "47 archivos modificados" ≠ 47 cambios. El corpus de documentación llegó a contradecirse porque se escribía desde la intención, no desde la salida de comandos.

**Regla madre (ya en las instrucciones del proyecto, ahora con tres casos que la justifican):** ningún ✅ sin evidencia ejecutada — la salida de un comando, una respuesta HTTP, una corrida visible en un sistema externo. Si la evidencia no se puede producir, el estado es "desconocido", y se escribe "desconocido".

## Checklist anti-repetición (pre-push)

1. `node scripts/sync-asc-api.mjs --check` → exit 0.
2. `pytest backend/tests/test_asc_api_sync.py` → verde.
3. `git diff --ignore-cr-at-eol --stat` sobre lo staged si el diff parece inflado.
4. Cambio de API → hecho en `backend/asc_api` + sync, nunca directo en `frontend/asc_api`.
5. Nueva "protección" (gate, workflow, cron) → no se documenta como activa hasta verla ejecutar una vez.
