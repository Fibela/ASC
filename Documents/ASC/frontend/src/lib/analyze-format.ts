/**
 * Lógica pura del Análisis de Artefactos (/analyze).
 *
 * Extraída de la página para poder testearla SIN DOM y, sobre todo, para que
 * las pruebas validen el CÓDIGO REAL que se ejecuta en producción — no una
 * copia. (La auditoría marcó "los tests validan la documentación, no el
 * sistema" como anti-patrón; esto lo evita.) Ver docs/AUDIT_LOG.md (S120).
 */

// Límite efectivo impuesto por la plataforma serverless (Vercel ~4.5 MB de
// cuerpo de request). Guardamos margen: por encima de esto el request muere
// con 413 ANTES de llegar al backend, así que lo rechazamos del lado del cliente.
export const MAX_FILE_MB = 4
export const MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024

/** Formatea un tamaño en bytes a B / KB / MB legible. `—` si es nulo o 0. */
export function fmtBytes(n: number | null | undefined): string {
  if (!n) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}

/**
 * Valida el tamaño ANTES de subir. Devuelve un mensaje de error humano si el
 * archivo supera el límite de la plataforma, o `null` si es aceptable.
 */
export function validateFileSize(f: { name: string; size: number }): string | null {
  if (f.size > MAX_FILE_BYTES) {
    return `"${f.name}" pesa ${fmtBytes(f.size)} — supera el máximo de ~${MAX_FILE_MB} MB. Elige un archivo más pequeño.`
  }
  return null
}

/** Forma mínima de un error de axios/red que nos interesa interpretar. */
export interface AnalyzeError {
  code?: string
  message?: string
  response?: { status?: number; data?: { detail?: unknown } }
}

/**
 * Traduce errores de axios/red a un mensaje honesto para el usuario.
 * Cubre los dos casos reportados en producción: 413 (archivo > límite
 * serverless) y timeout (binario grande que tarda demasiado).
 */
export function errMessage(e: unknown): string {
  const err = e as AnalyzeError
  const status = err?.response?.status
  if (status === 413) {
    return `Archivo demasiado grande. El análisis soporta hasta ~${MAX_FILE_MB} MB en esta versión (límite de la plataforma serverless); los binarios grandes no se pueden subir aquí.`
  }
  if (err?.code === 'ECONNABORTED' || /timeout/i.test(err?.message ?? '')) {
    return 'El análisis tardó demasiado. Prueba con un archivo más pequeño; los binarios grandes no son soportados en esta versión.'
  }
  const detail = err?.response?.data?.detail
  if (typeof detail === 'string') return detail
  return err?.message || 'No se pudo completar el análisis.'
}
