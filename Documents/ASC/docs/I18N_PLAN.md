# Plan de Internacionalización (i18n) — Portal ASC

> **Estado:** PLAN (recon + diseño). No implementado. Cierra la fase **beta 1.0.0**.
> **Fecha:** 2026-07-28 · **Método:** verificación sobre el código y el sitio en vivo, no sobre READMEs.
> **Regla que gobierna este plan:** nada de traducciones inventadas. Si falta una traducción real, se dice; no se rellena con placeholder ni con máquina sin revisión.

---

## 1. Objetivo

Agregar al portal ASC los idiomas que ofrece el sitio oficial **premoscorp.com**, con
infraestructura real (no un widget de auto-traducción), preferencia persistente por usuario y
pruebas que garanticen que ningún idioma queda a medias.

Este documento es el **entregable de cierre de la beta 1.0.0**: define QUÉ, CÓMO y EN QUÉ ORDEN.
La implementación arranca en una fase posterior con tu visto bueno.

---

## 2. Evidencia del recon (verificada hoy)

### 2.1 Idiomas objetivo — del selector real de premoscorp.com

Inspeccionado en vivo con navegador (el sitio es client-rendered; el `<select>` de idioma expone):

| Código | Idioma      | Nota técnica                          |
|--------|-------------|---------------------------------------|
| es     | Español     | Base actual / fuente de verdad        |
| en     | English     | —                                     |
| pt     | Português   | —                                     |
| fr     | Français    | —                                     |
| de     | Deutsch     | —                                     |
| zh     | 中文 (chino)  | CJK — requiere fuente con glifos CJK  |
| ja     | 日本語 (japonés) | CJK — requiere fuente con glifos CJK |
| ar     | عربي (árabe) | **RTL** — requiere `dir="rtl"` y revisión de layout |

**8 idiomas.** Dos exigen trabajo extra más allá de traducir texto: **árabe (RTL)** y **CJK
(fuentes)**. El sitio declara `<html lang="es">` por defecto.

> No verificado (no bloquea el plan): si el sitio oficial traduce por ruta (`/en`) o por swap
> en cliente — la sonda quedó bloqueada por la capa de seguridad del navegador al leer datos de
> cookie/query. El portal ASC es una app distinta; su mecanismo lo decidimos aquí abajo.

### 2.2 Estado del portal ASC (código real)

- **Cero infraestructura i18n.** `package.json` sin `next-intl`/`i18next`/`react-intl`;
  `next.config.js` sin bloque `i18n`; no existen carpetas `messages/`, `locales/` ni `i18n/`.
- **Idioma fijo en código:** `frontend/src/app/layout.tsx` → `<html lang="es">` hardcodeado.
- **Superficie a traducir:** ~**31 archivos** con texto español embebido
  (28 de 34 páginas en `src/app/` + 3 de 9 en `src/components/`). Los strings están inline en el
  JSX, no en catálogos.
- **Sin selector de idioma** en el portal (el único "Idioma" es un campo de datos del honeypot,
  ajeno).
- **La capa de datos NO puede guardar la preferencia:** no existe columna `language`/`locale` en
  ningún modelo de `backend/asc_api/models/`. Persistir el idioma elegido **requiere migración**.

### 2.3 Contenido generado por el backend (queda en español)

- `services/reporter.py` genera reportes PDF/HTML con títulos y sello en español (`<html lang="es">`).
- `services/local_explainer.py` (motor de explicación adaptativa, S110) genera texto en español,
  variando por **perfil** (hogar/pyme/enterprise), **no por idioma**.

Consecuencia honesta: aunque se traduzca la UI, un usuario en inglés seguiría recibiendo el
**reporte** y la **explicación de alerta** en español hasta que se localice también ese contenido.
Eso es una decisión de alcance (ver Fase D), no un detalle.

### 2.4 Auditoría de paso (llaves / mocks / endpoints)

- Sin llaves hardcodeadas en `frontend/src` (los únicos `Bearer …` son tokens falsos en tests de
  auth). Superficie `NEXT_PUBLIC_*` = solo `API_URL` y `PORTAL_URL` (legítimo, no secretos).
- Sin mocks introducidos. El recon no tocó código de producción.

---

## 3. Decisión de arquitectura

Stack real: **Next.js (App Router) en Vercel Pro**. Sobre eso:

- **Recomendado: `next-intl`.** Es el estándar de i18n para App Router, funciona en Vercel
  serverless, soporta routing por locale con middleware y catálogos JSON. Bajo peso, sin backend
  propio de traducción.
- **Descartado: el `i18n` nativo de `next.config`.** Solo existe en Pages Router; en App Router no
  aplica. (Evita que alguien lo "arregle" copiándolo — no funcionaría.)
- **Alternativa pesada: `i18next`/`react-i18next`.** Más flexible pero más ceremonia; innecesaria
  para este caso.

**Routing:** segmento `app/[locale]/…` + `middleware.ts` que negocia el locale (preferencia
guardada → cookie → `Accept-Language` → `es` por defecto).

**Catálogos:** `frontend/messages/{es,en,pt,fr,de,zh,ja,ar}.json`. **`es.json` es la fuente de
verdad**; el resto debe tener exactamente sus mismas claves.

---

## 4. Alcance por capas (qué se traduce)

- **Capa 1 — Cáscara de UI (obligatoria):** navegación/`Sidebar`, botones, labels, estados vacíos,
  mensajes de error (p.ej. `errMessage` de `/analyze`), panel educativo de artefactos, títulos de
  módulos. ~31 archivos. Es el grueso del valor visible.
- **Capa 2 — Datos dinámicos de DB:** nombres de reglas de detección y alertas (muchos son términos
  técnicos MITRE, p.ej. "Brute Force Authentication"). Decisión: mayormente **no** traducir lo
  técnico; sí traducir etiquetas de estado/severidad. A definir regla por regla.
- **Capa 3 — Contenido generado (Fase D):** reportes PDF/HTML y motor de explicación. Requiere
  catálogos server-side o generación por idioma.

---

## 5. Persistencia de la preferencia

- Nueva columna **`users.language`** (VARCHAR, default `'es'`, `server_default` para
  retrocompatibilidad). Preferencia **por usuario**, no por tenant (un mismo tenant puede tener
  gente en distintos idiomas).
- **Migración Alembic** encadenada al head actual `b8f2a1c9d4e7`, con su `.sql` para correr en
  Supabase **ANTES del push** (lección del incidente I-3: esquema primero, código después).
- Fallback sin preferencia: `Accept-Language` del navegador.

---

## 6. Consideraciones especiales (no son opcionales)

- **Árabe = RTL.** `<html dir="rtl">` dinámico y revisión del layout (el `Sidebar` a la izquierda,
  flex, paddings) para que no se rompa en espejo.
- **CJK (中文 / 日本語).** La fuente actual `Inter` no trae glifos CJK → cargar `Noto Sans
  CJK`/`Noto Sans JP` o caer a fuentes del sistema para esos locales.
- **Fechas y números** por locale con `Intl.DateTimeFormat`/`Intl.NumberFormat` (no formatear a mano).

---

## 7. Enfoque de testing robusto

- **Test de paridad de claves (clave del plan):** un unit test carga los 8 JSON y verifica que cada
  catálogo tenga EXACTAMENTE las claves de `es.json` (sin faltantes ni sobrantes). Es JSON puro →
  **corre en el sandbox** (no necesita el binario SWC de Next que hoy bloquea a jest). Esto impide
  que un idioma se despliegue a medias.
- **Guard anti-hardcode:** regex/lint que falla si una página ya migrada conserva strings de texto
  embebidos en vez de `t('clave')`.
- **Typecheck aislado** de las páginas migradas + **jest en CI**.
- **Verificación en vivo** con navegador (cambiar idioma y leer la página, incluido el render RTL
  del árabe) antes de dar por buena cada fase.
- **Comandos** documentados en el AUDIT_LOG en cada corte, como en el resto del proyecto.

---

## 8. Riesgo mayor y decisión pendiente: ¿de dónde salen las traducciones?

Traducir 8 idiomas × ~31 superficies es mucho texto. **La regla del proyecto prohíbe inventar
datos** — y una traducción automática sin revisión al árabe/japonés/alemán es exactamente eso:
contenido no verificado presentado como bueno.

Antes de implementar necesito tu decisión sobre la fuente de las traducciones:

1. **Traductor humano / profesional** (máxima calidad, más lento/costoso).
2. **Servicio de traducción** (DeepL/Google) **con revisión** antes de publicar.
3. **El motor Fable 5** genera un primer borrador y tú/alguien revisa (coherente con el sello
   PremosCorp, pero exige revisión real).

Mi recomendación: **es.json + en.json** a mano/con revisión para la Fase A (tú dominas ambos), y
decidir el resto según presupuesto. Publicar un idioma a medio traducir daña más la marca que no
ofrecerlo aún.

---

## 9. Fases propuestas (fundador solo → fasear)

- **Fase A — Infra + ES/EN:** `next-intl`, `app/[locale]`, `middleware`, columna `users.language`
  (+ migración), selector de idioma en la UI, catálogos `es`/`en`, test de paridad de claves.
  Entregable mínimo vendible: portal bilingüe real.
- **Fase B — PT / FR / DE:** añadir catálogos, sin tocar infra.
- **Fase C — ZH / JA / AR:** fuentes CJK + RTL del árabe. Es la fase con más trabajo de layout.
- **Fase D (opcional) — Contenido generado:** localizar reportes y motor de explicación.

---

## 10. Decisiones abiertas (para ti)

1. Fuente de las traducciones (§8).
2. ¿Preferencia por **usuario** (recomendado) o por tenant?
3. ¿Se traducen nombres de reglas/alertas técnicas, o se dejan en su término estándar?
4. ¿Fase D (reportes/explicación en el idioma del usuario) entra ahora o después de vender?
5. ¿Arrancamos la Fase A como primer trabajo de la post-beta, o congelamos aquí?

---

*Documento vivo. Se actualizará al iniciar la implementación. Ninguna casilla se marca ✅ sin
evidencia de comando/verificación.*
