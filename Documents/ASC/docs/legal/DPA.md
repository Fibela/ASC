# Acuerdo de Procesamiento de Datos (DPA) — ASC (PremosCorp)

> **⚠️ BORRADOR — NO ES ASESORÍA LEGAL.** No soy abogado. El DPA es un contrato de alto riesgo;
> DEBE ser revisado y ajustado por un abogado especializado (GDPR + LFPDPPP) antes de firmarse.
> **Versión:** borrador 0.1 · [FECHA]

Este DPA forma parte de los Términos de Servicio entre **Corporación Premos** ("PremosCorp",
**Encargado/Procesador**) y el **Cliente** (**Responsable/Controlador**) y regula el
tratamiento de datos personales que PremosCorp realiza por cuenta del Cliente al prestar ASC
(p.ej. la telemetría de seguridad que el Cliente envía).

## 1. Objeto, naturaleza y duración

- **Objeto y naturaleza:** procesamiento de telemetría de seguridad, eventos, alertas e
  identificadores técnicos para prestar las funciones de ASC.
- **Finalidad:** exclusivamente ejecutar el servicio conforme a las instrucciones del Cliente.
- **Duración:** mientras esté vigente la suscripción, más los plazos de borrado del punto 8.
- **Categorías de titulares:** empleados/usuarios y sistemas de la organización del Cliente.
- **Tipos de datos:** identificadores técnicos (IP, hostname, usuario), metadatos de eventos
  de seguridad, y los que el Cliente decida enviar (ver Anexo I).

## 2. Instrucciones documentadas (GDPR 28.3.a)

PremosCorp tratará los datos **solo** conforme a las instrucciones documentadas del Cliente
(estos Términos + configuración de la plataforma). Si una ley obliga a otro tratamiento, lo
informará salvo prohibición legal.

## 3. Confidencialidad (28.3.b)

El personal autorizado de PremosCorp está sujeto a deberes de confidencialidad.

## 4. Seguridad (28.3.c / Art. 32)

PremosCorp implementa medidas técnicas y organizativas apropiadas: cifrado en tránsito y en
reposo, control de acceso por roles, **aislamiento multi-tenant**, firma criptográfica de la
telemetría del agente (Ed25519), registro de auditoría y monitoreo de disponibilidad. Detalle
en el Anexo II y en la Página de Seguridad.

## 5. Subencargados (28.2 / 28.3.d)

El Cliente autoriza de forma general el uso de los subencargados listados en el **Anexo III**
(hoy: Supabase — base de datos; Vercel — hosting; Stripe — pagos; Resend — correo; Anthropic —
explicación adaptativa). PremosCorp: (a) impondrá a cada subencargado obligaciones de
protección equivalentes; (b) notificará con antelación razonable la incorporación o cambio de
subencargados, permitiendo objeción fundada; (c) **responde frente al Cliente** por el
incumplimiento de sus subencargados.

## 6. Asistencia al Responsable (28.3.e/f)

PremosCorp asistirá razonablemente al Cliente para: atender solicitudes de derechos de los
titulares (ARCO / GDPR); cumplir obligaciones de seguridad, notificación de violaciones y
evaluaciones de impacto.

## 7. Notificación de violaciones de seguridad

PremosCorp notificará al Cliente **sin dilación indebida** tras tener conocimiento de una
violación que afecte datos personales tratados por cuenta del Cliente, con la información
disponible para que el Cliente cumpla sus obligaciones de notificación. [Definir plazo objetivo,
p.ej. 72 h, con abogado.]

## 8. Devolución y borrado (28.3.g)

A la terminación, y a elección del Cliente, PremosCorp devolverá o **borrará** los datos
personales, salvo obligación legal de conservarlos. [Definir plazos.]

## 9. Auditorías (28.3.h)

PremosCorp pondrá a disposición del Cliente la información necesaria para demostrar el
cumplimiento y permitirá auditorías razonables (p.ej. mediante reportes/certificaciones cuando
existan; ver roadmap SOC 2 en la Página de Seguridad).

## 10. Transferencias internacionales

Cuando existan transferencias fuera de la UE/EEE, se ampararán en **Cláusulas Contractuales
Tipo (SCCs)** aprobadas por la Comisión Europea u otro mecanismo válido. Para México, se
observará la LFPDPPP en materia de transferencias.

## 11. Responsabilidad

Se rige por la cláusula de responsabilidad de los Términos, sin perjuicio de las
responsabilidades imperativas de la normativa de protección de datos.

---

## Anexo I — Detalle del tratamiento
[Objeto, naturaleza, finalidad, duración, categorías de titulares y tipos de datos — concretar.]

## Anexo II — Medidas técnicas y organizativas
[Lista detallada: cifrado, control de acceso, aislamiento, auditoría, respaldo, gestión de
vulnerabilidades, etc. Enlazar a la Página de Seguridad.]

## Anexo III — Subencargados autorizados
| Subencargado | Función | Ubicación de datos | Mecanismo de transferencia |
|--------------|---------|--------------------|----------------------------|
| Supabase | Base de datos (PostgreSQL) | [REGIÓN] | [SCCs / adecuación] |
| Vercel | Hosting frontend/serverless | [REGIÓN] | [SCCs] |
| Stripe | Procesamiento de pagos | [REGIÓN] | [SCCs] |
| Resend | Correo transaccional | [REGIÓN] | [SCCs] |
| Anthropic | Explicación adaptativa de alertas | [REGIÓN] | [SCCs] |

---
*PremosCorp — "Cree en tu ambición." Borrador sujeto a validación legal profesional.*
