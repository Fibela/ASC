# Términos de Uso de la Plataforma ASC
## PremosCorp — Analizador de Seguridad Cibernética

**Versión:** 1.0  
**Fecha de vigencia:** 2026-06-18  
**URL de la plataforma:** https://asc.premoscorp.com  
**Contacto:** legal@premoscorp.com

---

> Estos Términos de Uso ("Términos") rigen el acceso y uso de la plataforma
> ASC — Analizador de Seguridad Cibernética, operada por PremosCorp.
> Al acceder a la plataforma, el usuario acepta estos Términos en su totalidad.

---

## 1. ACEPTACIÓN DE LOS TÉRMINOS

El acceso a la plataforma ASC implica la aceptación plena y sin reservas de estos
Términos. Si el usuario no acepta alguna de las condiciones, debe abstenerse de
usar la plataforma y notificar a su administrador de cuenta.

Estos Términos se complementan con:
- El Contrato de Servicios suscrito entre PremosCorp y la organización del usuario
- El Aviso de Privacidad de PremosCorp (disponible en premoscorp.com/privacidad)
- La Política de Uso Aceptable (Sección 5 de estos Términos)

En caso de conflicto, el Contrato de Servicios prevalece sobre estos Términos.

---

## 2. DESCRIPCIÓN DEL SERVICIO

La plataforma ASC es un sistema de monitoreo de seguridad cibernética que proporciona:

- **Dashboard SOC**: visualización en tiempo real de alertas, eventos e incidentes
- **Motor de Detección**: análisis de amenazas con correlación MITRE ATT&CK
- **Gestión de Incidentes**: workflow de respuesta, escalación y resolución
- **Threat Intelligence**: feeds de IoCs, TTPs y actores de amenaza
- **Forensics Ledger**: registro inmutable de eventos para análisis forense
- **Reportes**: ejecutivos, técnicos, métricas SOC y cumplimiento
- **Neutralización Asistida (PANL)**: acciones de contención con aprobación humana
- **Integraciones**: CrowdStrike Falcon, Palo Alto, Fortinet, Active Directory, SIEM

### 2.1 Acceso mediante SSO

El acceso a ASC se realiza **exclusivamente** mediante Single Sign-On (SSO) desde
premoscorp.com. No existe autenticación independiente por contraseña en la plataforma.

El usuario debe tener una cuenta activa en premoscorp.com con los permisos de
organización correspondientes para acceder a ASC.

### 2.2 Disponibilidad

La plataforma ASC está sujeta a los niveles de disponibilidad establecidos en el
SLA correspondiente al tier contratado. PremosCorp no garantiza disponibilidad
ininterrumpida pero sí los niveles acordados (99.9% / 99.5% según tier).

---

## 3. CUENTAS Y ACCESO

### 3.1 Credenciales y responsabilidad

- Cada usuario es responsable de mantener la confidencialidad de sus credenciales
  de acceso a premoscorp.com (que habilitan el SSO a ASC)
- El usuario no debe compartir sesiones activas ni credenciales con terceros
- En caso de sospecha de compromiso de cuenta, el usuario debe notificar
  inmediatamente a security@premoscorp.com

### 3.2 Roles y permisos

El acceso a funcionalidades dentro de ASC está controlado por roles:

| Rol | Capacidades |
|-----|------------|
| `viewer` | Solo lectura — dashboards, alertas, reportes |
| `analyst` | Viewer + gestión de incidentes, playbooks, búsqueda forense |
| `responder` | Analyst + acciones de neutralización (PANL) — requiere Human-in-the-Loop |
| `admin` | Acceso completo — configuración, gestión de usuarios, API keys, integraciones |

Los roles son asignados por el administrador de la cuenta de la organización.

### 3.3 Suspensión y terminación de acceso

PremosCorp podrá suspender o terminar el acceso de un usuario ante:
- Incumplimiento de estos Términos o de la Política de Uso Aceptable
- Solicitud de la organización contratante
- Actividad sospechosa o potencialmente maliciosa desde la cuenta
- Terminación del Contrato de Servicios de la organización

---

## 4. PROPIEDAD INTELECTUAL

### 4.1 Propiedad de PremosCorp

La plataforma ASC, incluyendo su código fuente, diseño, metodologías, algoritmos
de detección, reglas SIEM, modelos de ML, playbooks, y toda la documentación,
son propiedad intelectual exclusiva de PremosCorp y están protegidos por la
Ley Federal del Derecho de Autor y la legislación de propiedad industrial aplicable.

El usuario **no tiene derecho** a:
- Copiar, descompilar, hacer ingeniería inversa o modificar la plataforma
- Sublicenciar, vender o transferir el acceso a la plataforma
- Eliminar o modificar avisos de derechos de autor o marcas registradas
- Usar la plataforma para desarrollar un producto o servicio competidor

### 4.2 Propiedad del cliente

Los datos de seguridad de la organización del usuario (logs, alertas, eventos,
configuraciones de sistemas monitoreados) son y permanecen siendo propiedad
de la organización contratante. PremosCorp los trata exclusivamente para la
prestación del servicio contratado.

Los reportes generados por ASC basados en datos del cliente son propiedad del
cliente para uso interno de su organización.

### 4.3 Datos anónimos y mejora del servicio

PremosCorp podrá usar datos estadísticos y anonimizados (sin información que
permita identificar al cliente o sus sistemas) para mejorar la plataforma,
actualizar modelos de detección y publicar estadísticas del sector de ciberseguridad.

---

## 5. POLÍTICA DE USO ACEPTABLE

### 5.1 Usos prohibidos

El usuario **NO debe** usar la plataforma ASC para:

**Actividades ilegales:**
- Realizar o facilitar actividades que violen leyes locales o internacionales
- Acceder a sistemas de terceros no autorizados, incluso usando herramientas de ASC
- Interceptar comunicaciones sin autorización legal
- Lavado de dinero o financiamiento de actividades ilícitas

**Abuso de la plataforma:**
- Intentar acceder a datos de otras organizaciones en la plataforma
- Realizar pruebas de penetración sobre la infraestructura de ASC sin autorización escrita
- Automatizar solicitudes que sobrecarguen los servidores (abuso de API)
- Intentar eludir controles de acceso, autenticación o autorización
- Explotar vulnerabilidades de la plataforma sin reporte responsable

**Uso no autorizado de datos:**
- Exportar o compartir datos de clientes finales fuera de los sistemas del cliente
- Usar los datos procesados por ASC para fines distintos a la seguridad de la organización
- Revelar información de incidentes de seguridad a terceros no autorizados

### 5.2 Reporte responsable de vulnerabilidades (Bug Bounty)

Si el usuario descubre una vulnerabilidad en la plataforma ASC:

1. **Reportar inmediatamente** a security@premoscorp.com con asunto "VULN REPORT"
2. **No explotar** la vulnerabilidad más allá de lo necesario para confirmar su existencia
3. **No divulgar** públicamente hasta que PremosCorp haya tenido oportunidad de remediar
   (política de divulgación coordinada — 90 días)
4. **Incluir** en el reporte: descripción, pasos para reproducir, impacto potencial

PremosCorp reconocerá el reporte y coordinará la remediación. En función de la
severidad, PremosCorp podrá ofrecer reconocimiento público o compensación.

---

## 6. DATOS PROCESADOS POR ASC

### 6.1 Tipos de datos que ASC procesa

Durante la operación del servicio, ASC procesa:

| Tipo de dato | Origen | Propósito |
|-------------|--------|-----------|
| Logs de sistemas y red | Infraestructura del cliente | Detección de amenazas |
| Alertas de endpoints (CrowdStrike / Palo Alto) | Integraciones del cliente | Correlación y respuesta |
| Eventos de Active Directory | AD/LDAP del cliente | Detección de movimiento lateral |
| Metadatos de tráfico de red | Firewalls / IDS del cliente | Análisis de anomalías |
| IoCs (hashes, IPs, dominios) | Feeds de threat intel + hallazgos | Base de detección |
| Logs de acceso al portal ASC | Plataforma ASC | Seguridad de la plataforma |

### 6.2 Retención de datos en la plataforma

| Categoría | Retención en ASC | Extensión disponible |
|-----------|-----------------|---------------------|
| Eventos en tiempo real | 90 días (hot storage) | Hasta 1 año (cold) |
| Alertas e incidentes | 1 año | Hasta 5 años |
| Ledger forense (inmutable) | 2 años | Ilimitado (con costo adicional) |
| Reportes generados | 2 años | Indefinido |
| Logs de auditoría de la plataforma | 2 años | Según requerimiento legal |

### 6.3 Exportación y portabilidad

El usuario puede exportar sus datos en formatos estándar (JSON, CSV, PDF) en
cualquier momento mediante el portal ASC. Al terminar el contrato, el cliente
dispone de **60 días** para exportar sus datos antes de su eliminación de los
sistemas de PremosCorp.

---

## 7. LIMITACIÓN DE RESPONSABILIDAD

### 7.1 Limitación general

La responsabilidad de PremosCorp por el uso de la plataforma ASC está limitada
conforme a lo establecido en el Contrato de Servicios.

En ausencia de Contrato de Servicios específico:
- La responsabilidad máxima de PremosCorp se limita a **$0 USD** — el acceso
  sin contrato es estrictamente a título de prueba o demo, sin SLA ni garantías

### 7.2 Exención de responsabilidad

PremosCorp **no será responsable** por:

- Decisiones de seguridad tomadas por el cliente basadas en alertas o reportes de ASC
- Incidentes de seguridad que ocurran a pesar del monitoreo (fallos de detección
  inherentes a cualquier sistema de seguridad)
- Daños derivados del uso incorrecto de las herramientas de la plataforma
- Interrupciones del servicio dentro de los parámetros del SLA
- Acciones de neutralización ejecutadas por el cliente mediante las herramientas PANL

### 7.3 Indemnización por parte del usuario

El usuario acepta indemnizar y mantener indemne a PremosCorp ante cualquier
reclamación de terceros derivada de:
- Uso de la plataforma fuera de los Términos o la legislación aplicable
- Contenido o datos proporcionados por el usuario que infrinjan derechos de terceros
- Acciones de respuesta a incidentes tomadas por el usuario usando las herramientas ASC

---

## 8. INTEGRACIONES Y APIs

### 8.1 API de ASC

La API REST de ASC está disponible para usuarios con rol `admin`. Su uso está
sujeto a:
- Rate limits documentados en el portal (endpoints `/api/v1/rate-limits`)
- API Keys generadas y gestionadas por el administrador de la cuenta
- Las mismas restricciones de uso aceptable de la plataforma

### 8.2 Integraciones de terceros

PremosCorp no se hace responsable por el funcionamiento de plataformas de terceros
(CrowdStrike, Palo Alto, Fortinet, Microsoft AD) ni por cambios en sus APIs que
afecten las integraciones con ASC. PremosCorp mantendrá las integraciones actualizadas
con sus mejores esfuerzos.

---

## 9. MODIFICACIONES A LOS TÉRMINOS

PremosCorp podrá modificar estos Términos con **30 días de anticipación** mediante:
- Notificación por correo al administrador de la cuenta
- Banner en el portal ASC
- Publicación en premoscorp.com/legal/asc-terms

El uso continuado de la plataforma tras la fecha de vigencia de los cambios
constituye aceptación de los Términos actualizados.

Para cambios materiales que reduzcan los derechos del usuario, se requerirá
aceptación activa (checkbox en el portal al primer ingreso post-cambio).

---

## 10. DISPOSICIONES FINALES

### 10.1 Legislación aplicable

Estos Términos se rigen por las leyes de los **Estados Unidos Mexicanos**.
Las controversias se resolverán conforme a lo establecido en el Contrato de Servicios.

### 10.2 Divisibilidad

Si alguna disposición de estos Términos fuera declarada inválida, las demás
permanecerán en plena vigencia.

### 10.3 Contacto legal

Para consultas sobre estos Términos:  
**Correo:** legal@premoscorp.com  
**DPO (datos personales):** dpo@premoscorp.com  
**Seguridad / incidentes:** security@premoscorp.com

---

*Términos de Uso versión 1.0 — PremosCorp ASC — vigentes desde 2026-06-18*
