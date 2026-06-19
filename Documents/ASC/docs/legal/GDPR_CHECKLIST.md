# GDPR Compliance Checklist
## PremosCorp ASC — Clientes en la Unión Europea

**Versión:** 1.0  
**Última revisión:** 2026-06-18  
**Base legal:** Reglamento UE 2016/679 (GDPR)  
**Referencia interna:** ASC-GDPR-[AÑO]

---

> **Aplicabilidad**: Este checklist es obligatorio cuando ASC presta servicios a:
> - Empresas establecidas en la UE/EEE, independientemente de dónde operen
> - Empresas que monitorean o procesan datos de ciudadanos de la UE
> - Clientes que procesan datos de empleados o usuarios residentes en la UE

---

## MÓDULO 1 — Base Legal del Tratamiento (Art. 6 GDPR)

Antes de procesar cualquier dato personal de ciudadanos UE, identificar la base legal:

| # | Verificación | Estado | Artículo |
|---|-------------|--------|---------|
| 1.1 | Se ha identificado la base legal para CADA tipo de dato tratado | ☐ | Art. 6 |
| 1.2 | Consentimiento explícito obtenido donde se requiere (no asumido, ni pre-marcado) | ☐ | Art. 7 |
| 1.3 | El interés legítimo ha sido evaluado con un balance test documentado (si aplica) | ☐ | Art. 6(1)(f) |
| 1.4 | Para datos sensibles: base legal Art. 9 identificada (consentimiento explícito / obligación legal) | ☐ | Art. 9 |
| 1.5 | Las bases legales están documentadas en el Registro de Actividades de Tratamiento (RAT) | ☐ | Art. 30 |

**Bases legales disponibles bajo Art. 6:**
- (a) Consentimiento del interesado
- (b) Ejecución de un contrato
- (c) Cumplimiento de obligación legal
- (d) Protección de intereses vitales
- (e) Interés público o ejercicio de poder público
- (f) Interés legítimo del responsable

---

## MÓDULO 2 — Registro de Actividades de Tratamiento (Art. 30)

| # | Verificación | Estado |
|---|-------------|--------|
| 2.1 | Existe un RAT actualizado que documenta TODAS las actividades de tratamiento | ☐ |
| 2.2 | El RAT incluye: propósito, categorías de datos, destinatarios, transferencias internacionales | ☐ |
| 2.3 | El RAT incluye: plazos de conservación y medidas de seguridad por actividad | ☐ |
| 2.4 | El RAT está disponible para supervisores de protección de datos si lo solicitan | ☐ |
| 2.5 | El RAT se revisa y actualiza cuando hay cambios en el tratamiento | ☐ |

**Template de entrada en el RAT:**
```
Actividad: [nombre descriptivo]
Responsable: PremosCorp / [cliente como responsable conjunto]
Propósito: [finalidad específica]
Categorías de interesados: [empleados / clientes / usuarios / otros]
Categorías de datos: [identificativos / contacto / financieros / técnicos / sensibles]
Destinatarios: [internos / externos / terceros países]
Transferencias internacionales: [sí/no — mecanismo de garantía]
Plazo de retención: [período o criterios]
Medidas de seguridad: [cifrado / acceso restringido / anonimización / etc.]
```

---

## MÓDULO 3 — Derechos de los Interesados (Arts. 15–22)

| # | Derecho | Verificación | Plazo GDPR | Estado |
|---|---------|-------------|-----------|--------|
| 3.1 | **Acceso** (Art. 15) | Proceso definido para entregar copia de datos | 30 días | ☐ |
| 3.2 | **Rectificación** (Art. 16) | Proceso para corregir datos inexactos o incompletos | 30 días | ☐ |
| 3.3 | **Supresión** (Art. 17) | Proceso de "derecho al olvido" con criterios de elegibilidad | 30 días | ☐ |
| 3.4 | **Limitación** (Art. 18) | Posibilidad de "congelar" el tratamiento sin eliminar datos | 30 días | ☐ |
| 3.5 | **Portabilidad** (Art. 20) | Entrega de datos en formato estructurado y legible por máquina (JSON/CSV) | 30 días | ☐ |
| 3.6 | **Oposición** (Art. 21) | Proceso para atender oposición al tratamiento, incluyendo perfilado | Sin demora | ☐ |
| 3.7 | **No decisiones automatizadas** (Art. 22) | Revisión humana disponible si ASC genera perfiles de riesgo automáticos | Sin demora | ☐ |
| 3.8 | **Retirada de consentimiento** (Art. 7.3) | Mecanismo tan sencillo como el otorgamiento | Sin demora | ☐ |

**Checklist operativo para atender solicitudes:**
- [ ] Canal designado: dpo@premoscorp.com / privacidad@premoscorp.com
- [ ] Proceso de verificación de identidad antes de entregar datos (sin ser excesivo)
- [ ] Registro de todas las solicitudes recibidas y su resolución
- [ ] Coordinación con subencargados (Supabase, Vercel, Render) para cumplir en plazo
- [ ] Proceso de extensión de 60 días adicionales para casos complejos (con notificación)

---

## MÓDULO 4 — Transferencias Internacionales (Arts. 44–49)

Para cualquier transferencia de datos a países fuera del EEE:

| # | Verificación | Mecanismo | Estado |
|---|-------------|----------|--------|
| 4.1 | Identificados todos los destinos fuera del EEE donde se transfieren datos | — | ☐ |
| 4.2 | **México**: La Comisión Europea ha adoptado decisión de adecuación (verificar vigencia) | Decisión de adecuación | ☐ |
| 4.3 | **EE.UU. (Render/Vercel)**: DPF (Data Privacy Framework) o SCCs implementadas | SCCs o DPF | ☐ |
| 4.4 | **AWS/GCP**: SCCs firmadas con proveedor cloud | SCCs | ☐ |
| 4.5 | **Supabase**: Verificar adecuación o SCCs para región de datos | SCCs | ☐ |
| 4.6 | Las SCCs son las versiones actualizadas (Decisión de la Comisión 2021/914) | SCCs 2021 | ☐ |
| 4.7 | Transfer Impact Assessment (TIA) realizado para transferencias de alto riesgo | TIA | ☐ |
| 4.8 | El Aviso de Privacidad informa sobre las transferencias y mecanismos de garantía | — | ☐ |

**Estado de adecuación de México:**
> La Comisión Europea adoptó una Decisión de Adecuación para México en 2023.
> Verificar vigencia en: https://commission.europa.eu/law/adequacy-decisions_es

---

## MÓDULO 5 — Responsable del Tratamiento vs. Encargado (Arts. 4, 28, 29)

Clasificar el rol de PremosCorp en cada engagement:

| Escenario | Rol de PremosCorp | Rol del Cliente | Documento requerido |
|-----------|------------------|-----------------|---------------------|
| ASC monitorea sistemas DEL cliente y accede a datos de empleados/usuarios del cliente | **Encargado** | **Responsable** | DPA (Data Processing Agreement) |
| PremosCorp presta consultoría y solo trata datos del representante legal | **Responsable** independiente | **Responsable** independiente | Aviso de Privacidad propio |
| Ambas partes determinan conjuntamente los fines y medios | **Corresponsables** | **Corresponsables** | Acuerdo de corresponsabilidad (Art. 26) |

### 5.1 Checklist DPA (Art. 28) — cuando PremosCorp actúa como Encargado

Un DPA debe incluir obligatoriamente:

| # | Cláusula obligatoria | Estado |
|---|---------------------|--------|
| 5.1.1 | Objeto, duración, naturaleza y finalidad del tratamiento | ☐ |
| 5.1.2 | Tipo de datos personales y categorías de interesados | ☐ |
| 5.1.3 | Obligaciones y derechos del Responsable | ☐ |
| 5.1.4 | Instrucción documentada: PremosCorp solo trata según instrucciones del cliente | ☐ |
| 5.1.5 | Confidencialidad del personal autorizado para el tratamiento | ☐ |
| 5.1.6 | Medidas de seguridad técnicas y organizativas (Art. 32) | ☐ |
| 5.1.7 | Condiciones para autorizar subencargados (lista de subencargados aprobados) | ☐ |
| 5.1.8 | Asistencia al responsable en el ejercicio de derechos ARCO/GDPR | ☐ |
| 5.1.9 | Devolución o supresión de datos al finalizar el servicio | ☐ |
| 5.1.10 | Poner a disposición toda la información necesaria para auditorías | ☐ |

**Subencargados actuales de PremosCorp que procesan datos de clientes UE:**

| Subencargado | Ubicación | Función | Mecanismo |
|-------------|-----------|---------|----------|
| Supabase Inc. | EE.UU. / UE (Frankfurt) | Base de datos PostgreSQL | SCCs |
| Vercel Inc. | EE.UU. | Hosting frontend ASC | SCCs / DPF |
| Render Inc. | EE.UU. | Hosting backend FastAPI | SCCs |
| Resend Inc. | EE.UU. | Envío de notificaciones por correo | SCCs |

---

## MÓDULO 6 — Evaluación de Impacto (DPIA — Art. 35)

Una DPIA es **obligatoria** cuando el tratamiento implica:

| # | Supuesto de DPIA obligatoria | ¿Aplica a ASC? | Estado |
|---|---------------------------|----------------|--------|
| 6.1 | Evaluación sistemática y exhaustiva de personas (perfilado automatizado) | Potencialmente — alertas automáticas de riesgo | ☐ |
| 6.2 | Tratamiento a gran escala de datos sensibles (salud, biométricos, penales) | Si el cliente tiene datos de salud en sus sistemas | ☐ |
| 6.3 | Monitoreo sistemático de zonas de acceso público | Si el cliente tiene CCTV / sensores físicos en scope | ☐ |
| 6.4 | Tratamiento de datos de personas vulnerables (menores, empleados, pacientes) | Si el cliente los tiene | ☐ |
| 6.5 | Uso de nuevas tecnologías (IA, ML, biometría) | ASC usa ML para detección — evaluar | ☐ |

**Si aplica algún supuesto, la DPIA debe:**
- [ ] Describir el tratamiento y sus fines
- [ ] Evaluar la necesidad y proporcionalidad
- [ ] Identificar y valorar riesgos para los derechos de los interesados
- [ ] Establecer medidas de mitigación
- [ ] Consultar con el DPO antes de iniciar el tratamiento
- [ ] Consultar a la autoridad supervisora si el riesgo residual es alto (Art. 36)

---

## MÓDULO 7 — Seguridad y Brechas (Arts. 32–34)

### 7.1 Medidas técnicas y organizativas (Art. 32)

| # | Medida | Implementada en ASC | Estado |
|---|--------|---------------------|--------|
| 7.1.1 | Seudonimización de datos personales donde sea posible | En logs y análisis forense | ☐ |
| 7.1.2 | Cifrado de datos en tránsito (TLS 1.3) | Todas las comunicaciones ASC | ✅ |
| 7.1.3 | Cifrado de datos en reposo (AES-256) | Supabase + backups | ✅ |
| 7.1.4 | Capacidad de garantizar confidencialidad, integridad, disponibilidad y resiliencia | SLA documentado | ✅ |
| 7.1.5 | Proceso de restauración rápida en caso de incidente (MTTR < 4h para P1) | Definido en SLA | ✅ |
| 7.1.6 | Evaluación y prueba periódica de las medidas de seguridad | Pentest anual + auditorías | ☐ |
| 7.1.7 | MFA para todos los accesos internos a sistemas que procesan datos UE | Implementado | ✅ |
| 7.1.8 | Principio de minimización de datos (solo datos necesarios) | Revisar por módulo | ☐ |
| 7.1.9 | Principio de privacidad por diseño y por defecto (Art. 25) | Revisar nuevas features | ☐ |

### 7.2 Gestión de brechas de seguridad (Arts. 33–34)

| # | Verificación | Plazo | Estado |
|---|-------------|-------|--------|
| 7.2.1 | Procedimiento documentado de detección y clasificación de brechas | — | ☐ |
| 7.2.2 | Notificación a la autoridad supervisora si la brecha entraña riesgo | **72 horas** post-conocimiento | ☐ |
| 7.2.3 | Notificación a los interesados si la brecha entraña alto riesgo para sus derechos | Sin dilación indebida | ☐ |
| 7.2.4 | Registro interno de TODAS las brechas (incluso si no requieren notificación) | — | ☐ |
| 7.2.5 | Proceso de coordinación cliente–PremosCorp para brechas en sistemas en scope | — | ☐ |

**Template de registro de brecha:**
```
ID de brecha: ASC-BREACH-[AÑO]-[NÚMERO]
Fecha de detección: 
Fecha de conocimiento:
Naturaleza: [acceso no autorizado / pérdida / divulgación / destrucción]
Categorías de datos afectados:
Número aproximado de interesados:
Posibles consecuencias:
Medidas adoptadas:
¿Notificación a autoridad?: [Sí/No] — Fecha:
¿Notificación a interesados?: [Sí/No] — Fecha:
```

---

## MÓDULO 8 — DPO (Data Protection Officer — Art. 37)

Un DPO es **obligatorio** para PremosCorp cuando:

| # | Supuesto | ¿Aplica? |
|---|---------|---------|
| 8.1 | Autoridad u organismo público | No |
| 8.2 | Tratamiento a gran escala que requiera observación habitual y sistemática | **Sí — monitoreo continuo SOC** |
| 8.3 | Tratamiento a gran escala de datos especiales (Art. 9) o penales (Art. 10) | Potencialmente |

**Estado del DPO de PremosCorp:**
- [ ] DPO designado: [NOMBRE]
- [ ] DPO publicado en el Aviso de Privacidad y comunicado a la autoridad supervisora
- [ ] DPO con conocimientos especializados en legislación y práctica de protección de datos
- [ ] DPO independiente (no toma decisiones sobre los fines del tratamiento)
- [ ] Recursos suficientes asignados al DPO para cumplir sus funciones

---

## MÓDULO 9 — Información a los Interesados (Arts. 13–14)

Verificar que el Aviso de Privacidad (ver AVISO_PRIVACIDAD.md) incluye:

| # | Elemento obligatorio | Estado |
|---|---------------------|--------|
| 9.1 | Identidad y datos de contacto del Responsable | ✅ (en AVISO_PRIVACIDAD.md) |
| 9.2 | Datos de contacto del DPO | ✅ |
| 9.3 | Fines y base legal del tratamiento | ✅ |
| 9.4 | Intereses legítimos perseguidos (si aplica) | ☐ — detallar por caso |
| 9.5 | Destinatarios de los datos | ✅ |
| 9.6 | Transferencias a terceros países y garantías | ✅ |
| 9.7 | Período de conservación | ✅ |
| 9.8 | Derechos ARCO + portabilidad + oposición + no decisiones automatizadas | ✅ |
| 9.9 | Derecho a presentar reclamación ante autoridad supervisora | ✅ |
| 9.10 | Si el tratamiento es obligatorio o voluntario y consecuencias de no facilitar datos | ☐ — añadir |
| 9.11 | Existencia de decisiones automatizadas + lógica aplicada (si hay perfilado) | ☐ — evaluar ASC ML |

---

## MÓDULO 10 — Revisión y Auditoría

| Actividad | Frecuencia | Responsable | Próxima fecha |
|-----------|-----------|-------------|--------------|
| Revisión del RAT | Semestral | DPO | [FECHA] |
| Revisión del Aviso de Privacidad | Anual o ante cambios | DPO + Legal | [FECHA] |
| Auditoría de subencargados | Anual | DPO + Operaciones | [FECHA] |
| Verificación de SCCs vigentes | Anual | Legal | [FECHA] |
| Revisión de DPIA existentes | Ante cambios significativos | DPO | Ad-hoc |
| Capacitación en protección de datos al personal | Anual | RR.HH. + DPO | [FECHA] |
| Reporte al Consejo / Dirección | Trimestral | DPO | [FECHA] |

---

## RESUMEN DE ESTADO GDPR

| Módulo | Descripción | Completado |
|--------|-------------|-----------|
| 1 | Base legal del tratamiento | ☐ |
| 2 | Registro de Actividades (RAT) | ☐ |
| 3 | Derechos de los interesados | ☐ |
| 4 | Transferencias internacionales | ☐ |
| 5 | Responsable vs. Encargado / DPA | ☐ |
| 6 | DPIA | ☐ |
| 7 | Seguridad y brechas | ☐ |
| 8 | DPO | ☐ |
| 9 | Información a los interesados | ☐ |
| 10 | Revisión y auditoría | ☐ |

**Puntuación mínima para engagement con cliente UE:** Módulos 1, 2, 3, 4, 5 y 7 completados.

---

*GDPR Checklist versión 1.0 — PremosCorp ASC — 2026*  
*Basado en GDPR Reglamento UE 2016/679 y directrices del EDPB*  
*Consultar con especialista en derecho europeo de datos para clientes en UE*
