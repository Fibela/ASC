# Rediseño VALT — decisión de alcance (keep / suprimir)

**Sesión S117 (2026-07-23).** Criterio de Alexander: *"que se vea limpia; suprimir los
módulos inaccesibles, sin funcionamiento y los que no podemos hacer correr por normas;
los que se queden deben estar vivos leyendo datos reales en tiempo real."*

El sentido del producto (VALT) es analizar la seguridad de la navegación **en vivo**, así
que lo que quede debe leer datos reales de Supabase, no maquetas.

## Suprimido (solo UI — el backend queda dormido, testeado, auth-gated)

Se borraron las páginas y sus enlaces del Sidebar. Los endpoints/servicios del backend
NO se tocaron (siguen existiendo, sin exponerse en la interfaz) para no romper tests,
crons ni la auto-respuesta de /incidents.

| Ruta | Motivo |
|------|--------|
| `/neutralize` | Declara ejecutar acciones (bloquear/aislar/matar/deshabilitar) que **sin infra solo simulan** (honesto tri-estado, pero no neutraliza). No ejecutable por normas para fundador-solo sin SOC. |
| `/soar` | Orquesta el neutralizador simulado. Misma razón. |
| `/playbooks` | Automatiza acciones de respuesta simuladas. Misma razón. |
| `/pids` | Acciones de identidad (deshabilitar cuenta vía AD) que requieren infra AD que no tenemos. |
| `/adapters` | Config de firewall/AD/EDR; sin respuesta activa queda casi sin uso. |
| `/correlation` | Motor real y funcional, pero no encaja en el VALT / sale vacío en piloto de un tenant. |
| `/pricing` | Depende de Stripe configurado (checkout real); fuera del alcance actual del portal. |

**Reposicionamiento honesto:** ASC queda en su terreno sólido y defendible —
**detectar + explicar + recomendar** (la propia filosofía del proyecto: "explica y
recomienda; nunca ejecuta"). Se elimina la promesa de "neutralización" que no se puede
sostener.

## Se queda (funciona con datos reales)

Monitoreo en vivo (ya refrescan): `/` `/alerts` `/events` `/incidents` `/agents`
`/honeypot` `/ops` `/status`.
Análisis/otros (cargan al montar — PENDIENTE ponerlos en tiempo real, S117.3):
`/detection` `/threat-hunting` `/threat-intel` `/iocs` `/forensic` `/analyze`
`/metrics` `/reports` `/reports/executive`.
Plataforma/admin: `/admin` `/api-keys` `/rate-limits` `/webhooks`.

## Módulo de detección — veredicto de credibilidad (foco de Alexander)

El motor ES real y honesto (no stub, no mock): `evaluate_event` corre 4 reglas
hardcodeadas MITRE-mapeadas (DET-001 acord32/T1036.005, DET-002 hooks/T1056.001,
DET-003 persistencia registro/T1547.001, DET-004 tráfico diferido C2/T1071.001), y el
catálogo que muestra la UI sale de la DB sembrada con **exactamente esas 4** (migración
b3c4d5e6f7a8) → catálogo == motor, sin reglas fantasma.

**La credibilidad cojea por AMPLITUD, no por falsedad:** solo 4 reglas, una muy nicho
(acord32.exe). Un producto de seguridad creíble necesita cobertura más ancha (fuerza
bruta, PowerShell/LOLBins, volcado de credenciales, movimiento lateral…). Además la
lógica está hardcodeada (agregar fila en DB no agrega evaluación). **PENDIENTE (S117.4):
ampliar el ruleset** para que `/detection` sostenga el nombre ASC.

## Pendientes
- S117.3: poner en tiempo real las páginas de análisis que cargan al montar.
- S117.4 ✅ HECHO: motor editable (condiciones JSON en DB, sin código) + 10 reglas nuevas (DET-005..014).
- Backend dormido: los endpoints suprimidos siguen auth-gated; evaluar retirarlos del
  router en una tanda futura si se confirma que no se re-introducen.
