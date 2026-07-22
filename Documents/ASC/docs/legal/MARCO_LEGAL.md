# Marco Legal — PremosCorp ASC

**Versión:** 1.0  
**Última revisión:** 2026-06-18  
**Jurisdicción primaria:** México (con cláusulas de extensión GDPR)  
**Estado:** Template — revisión legal profesional requerida antes de uso con clientes

---

## 1. Fundamento legal de las operaciones ASC

PremosCorp ASC presta servicios de ciberseguridad que incluyen análisis de vulnerabilidades,
pruebas de penetración controladas, monitoreo de seguridad y respuesta a incidentes.
Todas las actividades operativas se rigen por el siguiente stack legal:

| Documento | Propósito | Obligatorio |
|-----------|-----------|-------------|
| Carta de Autorización | Habilita cualquier prueba activa sobre sistemas del cliente | **Siempre** |
| Contrato de Servicios | Define alcance, entregables, tarifas y responsabilidades | **Siempre** |
| NDA Bilateral | Protege información confidencial de ambas partes | **Siempre** |
| Aviso de Privacidad | LFPDPPP / GDPR — tratamiento de datos personales | **Siempre** |
| Acuerdo de Nivel de Servicio (SLA) | Tiempos de respuesta y garantías | Servicios continuos |
| Acuerdo de Subcontratación | Cuando se involucran terceros | Si aplica |

---

## 2. Jerarquía de documentos

```
CONTRATO DE SERVICIOS (documento maestro)
  ├─ Anexo A: Carta de Autorización (por engagement)
  ├─ Anexo B: NDA Bilateral
  ├─ Anexo C: Aviso de Privacidad
  ├─ Anexo D: Alcance técnico (Statement of Work / SoW)
  └─ Anexo E: Tarifas y condiciones de pago
```

El Contrato de Servicios es el documento maestro. Los Anexos se incorporan por referencia
y son vinculantes con la misma fuerza legal.

---

## 3. Marco normativo aplicable

### México
- **LFPDPPP** — Ley Federal de Protección de Datos Personales en Posesión de los Particulares
  (nueva ley vigente desde el 21 de marzo de 2025, que abrogó la LFPDPPP de 2010)
- **RLFPDPPP** — Reglamento de la LFPDPPP (2011)
- **Autoridad supervisora** — Secretaría Anticorrupción y Buen Gobierno (asumió las funciones
  del extinto INAI desde el 21/03/2025). Verificar lineamientos/normativa secundaria vigente.
- **LFTAIP** — Ley Federal de Transparencia y Acceso a la Información Pública
- **CFF** — Código Fiscal de la Federación (facturación electrónica CFDI)
- **LFCE** — Ley Federal de Comercio Electrónico
- **CP Federal Art. 211 bis** — Acceso ilícito a sistemas y equipos de informática

### Internacional (usuarios/clientes fuera de México)
- **GDPR** (UE) — Reglamento General de Protección de Datos 2016/679
- **CCPA** (California, EE.UU.) — California Consumer Privacy Act
- **LGPD** (Brasil) — Lei Geral de Proteção de Dados Pessoais

### Estándares técnicos con peso contractual
- ISO/IEC 27001:2022 — SGSI
- ISO/IEC 27017 — Seguridad en servicios cloud
- NIST CSF 2.0 — Cybersecurity Framework
- OWASP Testing Guide v4.2 — referencia metodológica

---

## 4. Principios operativos irrenunciables

### 4.1 Autorización previa siempre

> **Regla absoluta**: Ningún analista de PremosCorp ejecutará prueba activa, escaneo,
> acceso a red, inyección, fuzzing, ni ninguna técnica de evaluación sobre sistemas
> del cliente sin Carta de Autorización firmada por representante legal autorizado.

Este principio protege al cliente, a PremosCorp y a los analistas individualmente.
El CP Federal Art. 211 bis puede implicar penas de 6 meses a 2 años de prisión
por acceso no autorizado, incluso con intención legítima.

### 4.2 Scope estricto

Las pruebas se ejecutan **exclusivamente** dentro del alcance técnico definido en el Anexo D.
Descubrimientos incidentales fuera del scope se reportan y se suspende la exploración.

### 4.3 Principio de mínimo impacto

Los servicios ASC priorizan técnicas no destructivas. Cualquier técnica con riesgo
de interrupción (DoS, modificación de datos) requiere autorización explícita adicional
y ventana de mantenimiento acordada.

### 4.4 Confidencialidad total

Toda la información obtenida durante los servicios es confidencial por defecto.
No se comparte con terceros, no se usa como referencia comercial sin autorización escrita,
no se retiene más allá del período acordado.

---

## 5. Clasificación de información del cliente

| Nivel | Ejemplos | Retención | Destrucción |
|-------|---------|-----------|-------------|
| CRÍTICA | Credenciales, llaves privadas, datos personales sensibles | 0 días post-engagement | Inmediata / certificada |
| CONFIDENCIAL | Hallazgos, arquitectura de red, configuraciones | 90 días | Segura verificada |
| RESTRINGIDA | Informes ejecutivos, metodologías aplicadas | 1 año | Segura |
| INTERNA | Logs de proyecto, comunicaciones | 2 años | Estándar |

---

## 6. Seguros recomendados

PremosCorp debe mantener vigentes:

| Seguro | Cobertura mínima recomendada | Notas |
|--------|------------------------------|-------|
| Cyber Liability | $1,000,000 USD | Cubre violaciones de datos, ransomware, errores en el servicio |
| E&O (Errors & Omissions) | $500,000 USD | Negligencia profesional, fallos en detección |
| Responsabilidad Civil General | $300,000 USD | Daños a terceros durante operaciones |

> Proveedores activos en México: Chubb, AIG, Zurich, HDI Seguros (ramos de responsabilidad tech).
> Solicitar cotización como "empresa de servicios de tecnología de la información y ciberseguridad".

---

## 7. Proceso de onboarding legal de nuevo cliente

```
1. Firma NDA Bilateral (antes de cualquier intercambio de información)
   ↓
2. Discovery comercial (sin revelar arquitectura interna del cliente)
   ↓
3. Firma Contrato de Servicios + Aviso de Privacidad + SoW (Anexo D)
   ↓
4. Firma Carta de Autorización (por cada engagement activo)
   ↓
5. Kick-off técnico — inicio de servicios
   ↓
6. Reporte final + sesión de resultados
   ↓
7. Destrucción certificada de información CRÍTICA
   ↓
8. Facturación CFDI + cierre de engagement
```

---

## 8. Checklist legal mínimo por engagement

- [ ] NDA bilateral firmado por representante con poder notarial o equivalente
- [ ] Contrato de Servicios firmado (todas las páginas rubricadas)
- [ ] Carta de Autorización con IP ranges, sistemas y fechas específicas
- [ ] Aviso de Privacidad entregado y acuse de recibo
- [ ] SoW / Alcance técnico con exclusiones explícitas
- [ ] Contacto de emergencia del cliente disponible 24/7
- [ ] Ventana de pruebas acordada (horario de menor impacto)
- [ ] Canal de comunicación seguro establecido (Signal / correo con S/MIME)
- [ ] Política de escalación ante hallazgos críticos acordada

---

## 9. Documentos en este directorio

| Archivo | Descripción |
|---------|-------------|
| `AUTORIZACION_PENTEST.md` | Template: Carta de Autorización para pruebas activas (obligatoria antes de cualquier pentest) |
| `CONTRATO_SERVICIOS.md` | Template: Contrato Marco de Servicios de Ciberseguridad (documento maestro) |
| `NDA_BILATERAL.md` | Template: Acuerdo de No Divulgación Bilateral (firmar ANTES del discovery) |
| `AVISO_PRIVACIDAD.md` | Template: Aviso de Privacidad (LFPDPPP + GDPR — derechos ARCO + portabilidad) |
| `SLA_SERVICIOS.md` | Template: Service Level Agreement (uptime 99.9%, tiempos de respuesta, créditos) |
| `GDPR_CHECKLIST.md` | Checklist de cumplimiento GDPR (10 módulos — obligatorio para clientes UE) |
| `TERMINOS_USO_PLATAFORMA.md` | Términos de Uso del portal ASC (roles, uso aceptable, API, retención de datos) |

---

*Este marco legal es un punto de partida. Consultar con abogado especializado en
derecho tecnológico y protección de datos antes de formalizar contratos con clientes.*
