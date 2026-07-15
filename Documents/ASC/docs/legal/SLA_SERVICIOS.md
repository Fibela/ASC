# Acuerdo de Nivel de Servicio (SLA)
## PremosCorp — Analizador de Seguridad Cibernética (ASC)

**Versión:** 1.0  
**Última revisión:** 2026-06-18  
**Clasificación:** CONFIDENCIAL  
**Referencia:** ASC-SLA-[AÑO]-[NÚMERO]  
**Incorporado como:** Anexo al Contrato ASC-SVC-[AÑO]-[NÚMERO]

---

## I. DEFINICIONES

| Término | Definición |
|---------|-----------|
| **Tiempo de Actividad (Uptime)** | Período en que la plataforma ASC está disponible y operativa |
| **Tiempo de Inactividad (Downtime)** | Período en que el servicio está no disponible, excluidas ventanas de mantenimiento programado |
| **Ventana de Mantenimiento** | Período programado para mantenimiento — por defecto: domingos 02:00–06:00 hrs (UTC-6) |
| **Incidente** | Evento que causa degradación o interrupción del servicio |
| **MTTR** | Mean Time to Recover — tiempo promedio de recuperación post-incidente |
| **MTTD** | Mean Time to Detect — tiempo promedio de detección de una amenaza |
| **Severidad Crítica** | CVSS ≥ 9.0 o impacto operacional inmediato en producción |
| **Periodo de Medición** | Calendario mensual (00:00:01 del día 1 a 23:59:59 del último día del mes) |

---

## II. ALCANCE DEL SLA

Este Acuerdo aplica a los siguientes componentes del servicio ASC:

| Componente | Descripción | Cobertura |
|-----------|-------------|-----------|
| **Portal ASC** (frontend) | Interfaz web en asc.premoscorp.com | 24/7/365 |
| **API ASC** (backend) | API REST en asc.premoscorp.com/api (Vercel serverless) | 24/7/365 |
| **Motor de Detección** | Procesamiento de alertas e IoCs en tiempo real | 24/7/365 |
| **Base de Datos** (Supabase) | PostgreSQL — persistencia de datos | 24/7/365 |
| **Notificaciones** | Alertas por correo, webhook, integración | 24/7/365 |
| **Plataforma de Reportes** | Generación de reportes ejecutivos y técnicos | Días hábiles |
| **Soporte Técnico** | Atención a incidentes y consultas | Según tier contratado |

---

## III. NIVELES DE SERVICIO GARANTIZADOS

### 3.1 Disponibilidad de la Plataforma

| Tier | Disponibilidad mensual garantizada | Downtime máximo/mes | Aplica a |
|------|------------------------------------|---------------------|---------|
| **SOC Enterprise** | 99.9% | 43.8 minutos | Monitoreo continuo + ASC completo |
| **SOC Business** | 99.5% | 3.65 horas | Módulos seleccionados |
| **Assessments** | Sin SLA de uptime | N/A — proyectos puntuales | Pentests / VA |

**Cálculo de disponibilidad:**
```
Disponibilidad (%) = ((Minutos totales del mes - Minutos de Downtime) / Minutos totales del mes) × 100
```

*El downtime planificado (ventana de mantenimiento) NO se contabiliza como tiempo de inactividad.*

### 3.2 Tiempos de Respuesta a Incidentes de Seguridad

| Severidad | Criterio | Notificación inicial | Actualización de estado | Resolución objetivo |
|-----------|---------|---------------------|------------------------|---------------------|
| **P1 — CRÍTICA** | CVSS ≥ 9.0 / Brecha activa confirmada / Ransomware | **< 15 minutos** | Cada 30 minutos | < 4 horas |
| **P2 — ALTA** | CVSS 7.0–8.9 / Compromiso probable / Exfiltración | **< 1 hora** | Cada 2 horas | < 24 horas |
| **P3 — MEDIA** | CVSS 4.0–6.9 / Anomalía significativa | **< 4 horas** | Diaria | < 72 horas |
| **P4 — BAJA** | CVSS < 4.0 / Informativa | **< 24 horas** | En reporte semanal | 5 días hábiles |

*"Notificación inicial" = primer contacto al cliente confirmando que el incidente fue detectado y está siendo gestionado.*  
*"Resolución objetivo" = contención y erradicación, no necesariamente remediación completa.*

### 3.3 Tiempos de Respuesta de Soporte

| Canal | Tier Enterprise | Tier Business | Horario |
|-------|----------------|---------------|---------|
| Teléfono de emergencia | 24/7 | 24/7 (solo P1/P2) | Siempre |
| Signal / mensajería segura | < 15 min | < 1 hora | 24/7 |
| Correo electrónico | < 2 horas | < 8 horas hábiles | Horas hábiles |
| Portal de tickets | < 4 horas | < 12 horas hábiles | Horas hábiles |

**Horario de horas hábiles:** Lunes a viernes, 08:00–20:00 hrs (Tiempo del Centro, UTC-6)  
**Contacto de emergencia PremosCorp:** [NÚMERO] / security@premoscorp.com

### 3.4 Métricas de Detección (SOC Continuo)

| Métrica | Objetivo | Medición |
|---------|---------|---------|
| **MTTD** (tiempo de detección) | < 15 minutos para amenazas conocidas (IoC match) | Promedio mensual |
| **MTTR** (tiempo de contención) | < 4 horas para incidentes P1 | Promedio mensual |
| **Tasa de falsos positivos** | < 5% de alertas totales | Promedio mensual |
| **Cobertura de reglas activas** | ≥ 95% de reglas MITRE ATT&CK tier contratado | Mensual |
| **Actualización de IoCs** | < 24 horas desde fuentes de threat intel | Continuo |

---

## IV. VENTANAS DE MANTENIMIENTO

### 4.1 Mantenimiento programado

| Tipo | Horario por defecto | Frecuencia | Aviso mínimo |
|------|---------------------|-----------|--------------|
| Rutinario (parches, updates) | Dom 02:00–06:00 hrs UTC-6 | Mensual | 48 horas |
| Mayor (migraciones, upgrades) | Sábado 22:00 – Dom 06:00 hrs UTC-6 | Trimestral | 5 días |
| Emergencia (parches críticos CVE) | Cualquier horario | Ad-hoc | 2 horas |

### 4.2 Notificación de mantenimiento

PremosCorp notificará mantenimientos programados mediante:
- Correo al contacto técnico principal
- Banner en el portal ASC con 48 horas de anticipación
- Entrada en el canal de comunicación seguro acordado

---

## V. EXCLUSIONES DEL SLA

Los siguientes eventos **NO** cuentan como downtime para efectos de cálculo del SLA:

a) Ventanas de mantenimiento programado notificadas
b) Fuerza mayor: desastres naturales, cortes de energía masivos, eventos civiles
c) Incidentes causados por acciones del propio cliente (configuraciones incorrectas, abuso de API)
d) Interrupciones de proveedores de infraestructura terceros (Vercel, Supabase) que excedan los SLAs de esos proveedores
e) Ataques DDoS contra la infraestructura del cliente que saturen canales compartidos
f) Períodos en que el cliente no proporcionó acceso o información necesaria para la resolución
g) Interrupciones del servicio de Internet del cliente

---

## VI. CRÉDITOS POR INCUMPLIMIENTO DE SLA

Cuando la disponibilidad mensual real sea inferior a la garantizada:

### 6.1 Tabla de créditos (Tier Enterprise 99.9%)

| Disponibilidad real en el mes | Crédito sobre factura mensual |
|-------------------------------|-------------------------------|
| 99.0% – 99.8% | 5% |
| 98.0% – 98.9% | 10% |
| 95.0% – 97.9% | 15% |
| < 95.0% | 25% |

### 6.2 Tabla de créditos (Tier Business 99.5%)

| Disponibilidad real en el mes | Crédito sobre factura mensual |
|-------------------------------|-------------------------------|
| 99.0% – 99.4% | 5% |
| 97.0% – 98.9% | 10% |
| < 97.0% | 20% |

### 6.3 Proceso de reclamación de créditos

1. El cliente debe solicitar el crédito dentro de los **10 días hábiles** siguientes al fin del mes
2. Adjuntar evidencia del incidente (pantallazos, logs, tickets)
3. PremosCorp validará contra sus propios registros de monitoreo
4. El crédito se aplica en la siguiente factura — no es reembolsable en efectivo
5. El crédito máximo por mes no excederá el **30%** de la factura mensual
6. Los créditos son el recurso exclusivo por incumplimiento de uptime (no dan lugar a terminación)

---

## VII. REPORTES Y VISIBILIDAD

### 7.1 Reportes incluidos en el servicio

| Reporte | Frecuencia | Destinatario | Formato |
|---------|-----------|-------------|---------|
| Dashboard ASC en tiempo real | Continuo | Analistas cliente | Portal web |
| Resumen de alertas | Diario (automático) | Contacto técnico | Correo + Portal |
| Informe semanal de actividad | Semanal | Técnico + Gerencial | PDF |
| Reporte ejecutivo mensual | Mensual | C-Level / Dirección | PDF |
| Reporte de threat hunting | Mensual | CISO / Técnico | PDF técnico |
| Métricas de SLA | Mensual | Administrador del contrato | Dashboard + PDF |

### 7.2 Contenido del Reporte Ejecutivo Mensual

- Resumen de actividad: total de alertas, incidentes, resoluciones
- Top amenazas detectadas con clasificación MITRE ATT&CK
- Métricas de MTTD y MTTR del período
- Estado de cumplimiento del SLA (uptime, tiempos de respuesta)
- Vulnerabilidades críticas/altas pendientes de remediación
- Recomendaciones del mes
- Comparativa con el mes anterior

---

## VIII. GESTIÓN DEL SERVICIO

### 8.1 Reuniones de revisión

| Reunión | Frecuencia | Participantes | Duración |
|---------|-----------|--------------|---------|
| Revisión operativa | Semanal | Contacto técnico bilateral | 30 min |
| Revisión de servicio | Mensual | Técnico + Gerencial | 60 min |
| QBR (Quarterly Business Review) | Trimestral | Ejecutivo + CISO | 90 min |

### 8.2 Gestión de cambios

Cualquier cambio al alcance del servicio (nuevos sistemas, nuevas reglas, integraciones) debe:
1. Solicitarse formalmente por escrito (correo o portal de tickets)
2. Ser evaluado por PremosCorp en un plazo de 5 días hábiles
3. Si implica costo adicional: aprobación del cliente antes de implementar
4. Documentarse en Addendum al Contrato o Anexo D actualizado

---

## IX. ESCALACIÓN

### 9.1 Árbol de escalación PremosCorp

| Nivel | Rol | Contacto | Cuándo escalar |
|-------|-----|---------|---------------|
| L1 | Analista SOC | Duty analyst | Primera respuesta, tickets generales |
| L2 | Analista Senior | Rotation lead | Sin respuesta en SLA / P2 no resuelto en 8h |
| L3 | Gerente de Operaciones | [NOMBRE] / [TELÉFONO] | P1 / P2 sin contención en 4h |
| L4 | Director de Seguridad | [NOMBRE] / [TELÉFONO] | Brecha confirmada con impacto al negocio |
| L5 | CEO / Ejecutivo | [NOMBRE] / [TELÉFONO] | Impacto legal / regulatorio / reputacional |

### 9.2 Árbol de escalación del Cliente (rellenar en kick-off)

| Nivel | Nombre | Cargo | Teléfono | Correo |
|-------|--------|-------|---------|--------|
| Contacto técnico 1° | | | | |
| Contacto técnico 2° | | | | |
| Gerente / CISO | | | | |
| Ejecutivo decisor | | | | |

---

## X. VIGENCIA Y REVISIÓN

Este SLA tiene vigencia igual al Contrato de Servicios al que está anexado.  
Será revisado y actualizado **anualmente** o ante cambios significativos en el servicio.  
Cualquier modificación requiere Addendum firmado por ambas partes.

---

*SLA versión 1.0 — PremosCorp ASC — 2026*  
*Incorporado como Anexo al Contrato Marco ASC-SVC-[AÑO]-[NÚMERO]*
