<!-- TRAZABILIDAD -->
> **Versión:** ASC alfa 2.0.1 — snapshot de madurez de producto
> **Fecha de corte:** 2026-07-21
> **Lema:** *Cree en tu ambición.* — PremosCorp
> **Estado:** piloto/beta vendible con clientes seleccionados; P0 legales+piloto pendientes.
> **Trazabilidad:** este documento congela el estado verificado tras S105. Cualquier avance
> de los frentes (legal, piloto, operación) referencia esta línea base 2.0.1.

---

# Reporte de Madurez de Producto — ASC (PremosCorp)

**Fecha:** 2026-07-21
**Método:** verificación sobre el código y el despliegue en producción (no sobre READMEs).
**Alcance:** backend (`asc_api`), frontend (`src/app`), integraciones, core loop, CI/CD, estado de producción.

---

## Veredicto en una línea

ASC es **software real y funcional, no vaporware**, con aislamiento multi-tenant ahora
sólido y capacidad de cobro operativa. **Todavía NO está listo para venta masiva (GA) con
confianza**, pero **sí es promocionable como beta/piloto con clientes tempranos
seleccionados**. Faltan tres frentes: (1) el pilar de *respuesta* depende de infraestructura
que el cliente debe desplegar, (2) confianza/legal, y (3) operación 24/7 — crítica para un
producto de seguridad operado por un fundador solo.

---

## Lo que SÍ está (verificado en código y producción)

**Plataforma.** 37 endpoints, 28 modelos, 26 servicios, 29 migraciones, 95 archivos de test.
Frontend Next.js con 32 páginas (una por módulo: alerts, incidents, correlation, detection,
hunting, forensic, iocs, threat-intel, agents, adapters, admin, billing…), cliente API real
contra `/api/v1`, **sin mocks ni datos hardcodeados** en la UI.

**Producción viva.** Desplegado en `asc.premoscorp.com` (Vercel + Supabase). Último deploy
`READY` sobre el commit correcto; `readiness` = `ready` con `database:ok` y `schema:ok`.

**Seguridad y multi-tenant (endurecido en S102–S105).**
- Familia IDOR cerrada y con guardia AST anti-regresión en CI.
- Aislamiento por tenant en eventos, SOAR, incidentes, hunts, IoC, adaptencia, Threat Intel
  (2 capas) y reportes ejecutivos + PDF/HTML.
- Autenticación JWT (login/register/refresh/logout) + SSO + wizard de onboarding + roles.
- Enrollment de agentes SPECTER con token (`X-Specter-Token`), atado a tenant.
- Neutralizador **honesto**: ejecuta de verdad si hay adaptador/agente; si no, devuelve
  `simulated=True, success=False` explícito (nunca finge éxito).
- CI con gates: integridad de fuente única, IDOR, escaneo de secretos, esquema, y cobertura
  de backend ≥85%.

**Monetización mecánicamente lista.** Stripe integrado (checkout, portal, webhook con firma
HMAC verificada y anti-replay), catálogo de planes free/pro/enterprise en DB,
auto-provisioning de tenant al pagar. **Puede cobrar hoy.**

---

## Lo que FALTA para ser "vendible y rentable" con confianza

### Frente 1 — Producto / técnico

- **El pilar de RESPUESTA depende del cliente.** Detección, correlación, explicación y
  reportería funcionan. Pero la *neutralización* real requiere: (a) el agente SPECTER
  desplegado en los endpoints del cliente para acciones de host (aislar, matar proceso,
  cuarentena), y (b) adaptadores configurados (firewall PAN-OS/Fortinet, Active Directory)
  para bloqueo de red/identidad. **Sin esa infra, la respuesta es simulación honesta, no
  acción.** No es un bug — es honestidad — pero define cómo se puede promocionar.
- **Validación end-to-end con datos reales: NO verificada.** El flujo SPECTER→eventos→
  alertas→correlación→incidente→respuesta está cableado, pero no lo probé con un agente vivo
  enviando telemetría real a escala. Un piloto real es el siguiente paso de evidencia.
- **SPECTER como producto distribuible.** Es la fuente de datos; el cliente necesita
  instalarlo. Falta confirmar empaquetado, instalador, y guía de despliegue reproducible.
- **Carga/escala no probada.** Vercel serverless + Supabase aguantan un piloto; no hay
  prueba de carga que respalde promesas de volumen (EPS, retención, concurrencia).

### Frente 2 — Confianza / legal / compliance (bloqueante para vender a empresas)

- **Documentos legales:** Términos de Servicio, Política de Privacidad y **DPA (acuerdo de
  procesamiento de datos)**. Vender un producto que ingiere la telemetría de seguridad de
  otra empresa sin DPA es un no-arranque en cualquier compra B2B seria.
- **"¿Y tú qué tan seguro eres?"** Eres un producto de *seguridad*: el comprador auditará TU
  postura. Mínimo: página de seguridad, manejo de secretos documentado, cifrado en reposo/
  tránsito, y un **roadmap SOC 2 / ISO 27001** (aunque la certificación venga después).
- **Retención, borrado y residencia de datos** — política explícita (GDPR/LFPDPPP en México).

### Frente 3 — Go-to-market / operación (el más subestimado)

- **Operación 24/7.** Un cliente que compra un centro de seguridad espera que *alguien*
  vigile. Fundador solo = sin on-call, sin SOC, sin cobertura nocturna. Esto no bloquea un
  piloto self-service, pero sí limita a quién se le puede *recomendar* como defensa seria.
- **Soporte, SLA y documentación de cliente** (onboarding, runbooks, "cómo conectar mi EDR").
- **Onboarding self-serve completo** hasta el primer valor ("time-to-first-alert").
- **Validación comercial:** pricing probado con clientes reales y **un primer cliente/piloto**
  que confirme que el problema y la solución encajan.

---

## Cómo promocionarlo HONESTAMENTE hoy

Vendible **como piloto/beta** con este posicionamiento (defendible con el código actual):

> "Centro de seguridad multi-tenant que **detecta, correlaciona y explica** amenazas en
> lenguaje adaptado al cliente (hogar/pyme/enterprise), con **respuesta asistida** que se
> vuelve automática al integrar tu firewall/EDR/AD."

Lo que **NO** se debe prometer aún: "remediación autónoma total" o "SOC gestionado 24/7".
El neutralizador es honesto en el código; el marketing debe serlo igual.

---

## Definición de "Listo para vender v1" — checklist priorizado

**P0 (bloqueantes para cobrar a un tercero):**
- [ ] ToS + Política de Privacidad + DPA publicados y enlazados en el registro.
- [ ] Página de seguridad + política de manejo/retención/borrado de datos.
- [ ] Un piloto end-to-end real (SPECTER vivo → alerta → respuesta) documentado como evidencia.
- [ ] Guía de despliegue de SPECTER reproducible por el cliente.

**P1 (para recomendar con confianza):**
- [ ] Al menos un adaptador de respuesta real validado extremo-a-extremo (p.ej. bloqueo en firewall).
- [ ] Onboarding self-serve hasta "primera alerta".
- [ ] Plan de soporte + SLA mínimo + estado/monitorización de la plataforma.
- [ ] Prueba de carga básica que respalde las promesas de volumen.

**P2 (para escalar / rentabilizar):**
- [ ] Roadmap SOC 2 / ISO 27001 iniciado.
- [ ] Threat Intel 3 capas (ya diseñado en `docs/roadmap/`).
- [ ] Explainer en vivo (`ANTHROPIC_API_KEY` + panel UI) — ventaja competitiva ya cubierta en código.
- [ ] Rediseño UI VAULT.
- [ ] Modelo de costos/márgenes por tenant validado.

---

## Honestidad sobre lo NO verificado

Para no repetir el error de "documentar sobre estado desconocido": **no** verifiqué en esta
evaluación el flujo end-to-end con un agente SPECTER real emitiendo telemetría, ni pruebas de
carga, ni una auditoría ofensiva (pentest), ni cada uno de los 37 endpoints individualmente.
El veredicto se basa en: arquitectura y aislamiento verificados en código, salud de producción
en vivo, y el inventario real. Un **piloto controlado** es la forma correcta de convertir este
"funciona en el código" en "funciona con un cliente".

---

## Conclusión

ASC pasó de "13,181 líneas de documentación que se contradicen" a una plataforma con
seguridad multi-tenant verificada, CI que caza regresiones, y producción sana. **La ingeniería
central está en un punto vendible como piloto.** Lo que separa a ASC de un producto que se
puede *recomendar y rentabilizar con confianza* no es más código de features — es **evidencia
de un piloto real, la capa legal/de confianza, y un plan de operación** que reconozca que hoy
lo opera una sola persona. Cerrar los cuatro P0 te habilita a cobrarle a tu primer cliente sin
sobre-prometer.
