# Seguridad y Confianza — ASC (PremosCorp)

> **Nota:** esta página describe la postura de seguridad de ASC con honestidad. Los puntos
> marcados *(roadmap)* aún no están implementados; se listan para transparencia, no como
> afirmaciones de estado actual. **Versión:** borrador 0.1 · [FECHA]
>
> *Eres un producto de seguridad: tus clientes auditarán TU postura. Esta página es tu carta
> de confianza — mantenla veraz. Revisar redacción con abogado para no sobre-prometer.*

## Nuestro enfoque

ASC procesa telemetría de seguridad de nuestros clientes. Tratamos esa responsabilidad con la
misma seriedad que pedimos a nuestros clientes. Preferimos ser **honestos sobre lo que existe
y lo que falta** antes que prometer de más.

## Aislamiento multi-tenant

Cada cliente (tenant) ve únicamente sus propios datos. El aislamiento se aplica a nivel de
consulta en alertas, eventos, incidentes, correlación, threat intel, reportería y telemetría
de agentes. Contamos con un **guardia automático anti-IDOR** (análisis estático) que corre en
cada cambio de código para prevenir regresiones de fuga entre tenants.

## Autenticación y control de acceso

- Autenticación por JWT y **SSO** (Google/GitHub).
- Control de acceso **basado en roles** (viewer / analyst / admin).
- Enrolamiento de agentes SPECTER protegido por **token** (HMAC-SHA256, rotación horaria).

## Integridad de la telemetría

La telemetría de los agentes SPECTER se **firma criptográficamente (Ed25519)**; el servidor
verifica la firma antes de procesarla. En modo estricto, se rechaza toda telemetría con firma
inválida — impidiendo la inyección de eventos falsos.

## Cifrado

- **En tránsito:** HTTPS/TLS en todo el tráfico.
- **En reposo:** cifrado gestionado por nuestra capa de datos (Supabase/PostgreSQL).

## Prácticas de desarrollo seguro

- **Integración continua (CI)** que, en cada cambio, corre: escaneo de secretos, guardia
  anti-IDOR, verificación de esquema, y una suite de pruebas con **gate de cobertura ≥85%**.
- Fuente única de verdad para el backend, con verificación de integridad automática.
- Respuesta **honesta**: si una acción de contención no puede ejecutarse (falta el agente o el
  adaptador), el sistema la reporta como *simulada*, nunca como ejecutada.

## Subprocesadores

Ver la lista viva en el DPA (Anexo III): Supabase, Vercel, Stripe, Resend, Anthropic. Se
actualiza al incorporar o cambiar proveedores.

## Manejo de datos

- No vendemos datos personales.
- Retención y borrado conforme al DPA y al Aviso de Privacidad.
- [Definir residencia de datos y política de respaldos.]

## Reporte de vulnerabilidades

¿Encontraste un problema de seguridad? Escríbenos a **[seguridad@premoscorp.com]**. Nos
comprometemos a responder y a no emprender acciones legales contra investigación de buena fe
conforme a [POLÍTICA DE DIVULGACIÓN RESPONSABLE — definir].

## En el horizonte *(roadmap — aún no vigente)*

- *(roadmap)* Certificación **SOC 2 / ISO 27001**.
- *(roadmap)* Página de estado y monitoreo público.
- *(roadmap)* SLA formal de disponibilidad y soporte.
- *(roadmap)* Registros de auditoría exportables para el cliente.
- *(roadmap)* Botón de "generar token de agente" y onboarding self-service.

## Transparencia sobre nuestra etapa

ASC es operado actualmente por un equipo pequeño; **no ofrecemos vigilancia gestionada 24/7
(SOC)** en esta etapa. ASC es una herramienta de detección, explicación y respuesta asistida.
Comunicaremos con claridad cuando estas capacidades evolucionen.

---
*PremosCorp — "Cree en tu ambición." Borrador; validar redacción legal antes de publicar.*
