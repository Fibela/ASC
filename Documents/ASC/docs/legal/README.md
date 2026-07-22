# Documentos legales — ASC (PremosCorp)

> **⚠️ AVISO GENERAL — NO ES ASESORÍA LEGAL.** Todos los documentos de esta carpeta son
> **borradores/plantillas**. No soy abogado. Antes de publicarlos o vincular a un cliente,
> deben ser revisados, ajustados y validados por un abogado especializado en protección de
> datos y contratos tecnológicos (México + UE). Hay que rellenar todos los `[PLACEHOLDERS]`
> (domicilio, RFC, correos, plazos, jurisdicción).

## Estado (S107-Legal, 2026-07-22)

**Marco legal de referencia (verificado):** LFPDPPP de México **vigente desde el 21 de marzo
de 2025** (abrogó la de 2010; el INAI se extinguió y sus funciones pasaron a la **Secretaría
Anticorrupción y Buen Gobierno**), y **GDPR** (Art. 28) para clientes en la UE.

| Documento | Estado | Nota |
|-----------|--------|------|
| `AVISO_PRIVACIDAD.md` | preexistente, **actualizado a 2025** | referencias INAI/2010 corregidas |
| `TERMINOS_USO_PLATAFORMA.md` | preexistente | revisar y añadir caveat |
| `CONTRATO_SERVICIOS.md` | preexistente | contiene cláusulas de encargado — **reconciliar con `DPA.md`** |
| `DPA.md` | **NUEVO (S107)** | Art. 28 GDPR + subencargados; llena hueco real |
| `SEGURIDAD.md` | **NUEVO (S107)** | página de confianza, honesta (marca *roadmap* lo no vigente) |
| `MARCO_LEGAL.md` | preexistente, **actualizado a 2025** | referencia de ley corregida |
| `GDPR_CHECKLIST.md` | preexistente | también tiene lenguaje de encargado; alinear con DPA |
| `NDA_BILATERAL.md` | preexistente | revisar |
| `SLA_SERVICIOS.md` | preexistente | coherencia con "no SLA garantizado" de los Términos |
| `AUTORIZACION_PENTEST.md` | preexistente | revisar |

## Pendientes (para cerrar el P0 legal/confianza)

1. **Revisión legal profesional** de todo el set (bloqueante para publicar).
2. **Rellenar placeholders** (domicilio fiscal, RFC, correos de privacidad/seguridad/legal,
   plazos de notificación de brecha, jurisdicción, política de reembolsos/cancelación).
3. **Reconciliar DPA** con las cláusulas de encargado que ya viven en `CONTRATO_SERVICIOS.md`
   y `GDPR_CHECKLIST.md` (evitar contradicciones — mismo problema que ya nos mordió en el código).
4. **Versiones en inglés** para clientes internacionales (hoy todo en español).
5. **Publicar** enlazados en el registro/portal (Aviso simplificado en el alta electrónica).
6. Añadir el **caveat de abogado** a cada documento individual antes de distribuirlos sueltos.

## Hallazgo de método

Estos documentos legales YA existían y no los verifiqué antes de empezar a redactar — creé dos
duplicados inferiores que ya borré. Mismo aprendizaje que en el código: **revisar lo que existe
antes de crear.** Lo bueno: los preexistentes son sólidos como plantilla; solo estaban
desactualizados en la ley (2010→2025), ya corregido.

---
*PremosCorp — "Cree en tu ambición." Ningún documento de esta carpeta es válido sin revisión legal.*
