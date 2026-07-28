/**
 * Unit tests — Análisis de Artefactos, lógica pura (sin DOM).
 *
 * Importa el CÓDIGO REAL de src/lib/analyze-format.ts (no una copia), para
 * validar el sistema y no la documentación. Reproduce los dos errores que
 * reportó producción: archivo grande (arduino-ide.exe → 413/timeout) y el
 * mapeo honesto de esos fallos. Ver docs/AUDIT_LOG.md (S120).
 */
import { MAX_FILE_MB, MAX_FILE_BYTES, fmtBytes, validateFileSize, errMessage } from '@/lib/analyze-format'

describe('analyze-format · límite de tamaño', () => {
  it('MAX_FILE_BYTES deriva de MAX_FILE_MB', () => {
    expect(MAX_FILE_BYTES).toBe(MAX_FILE_MB * 1024 * 1024)
  })

  it('acepta un archivo pequeño (bajo el límite)', () => {
    expect(validateFileSize({ name: 'muestra.bin', size: 1024 })).toBeNull()
  })

  it('acepta un archivo justo en el límite', () => {
    expect(validateFileSize({ name: 'borde.bin', size: MAX_FILE_BYTES })).toBeNull()
  })

  it('rechaza un binario grande con mensaje claro (caso arduino-ide.exe)', () => {
    const msg = validateFileSize({ name: 'arduino-ide.exe', size: 180 * 1024 * 1024 })
    expect(msg).not.toBeNull()
    expect(msg).toContain('arduino-ide.exe')
    expect(msg).toContain(`${MAX_FILE_MB} MB`)
  })
})

describe('analyze-format · fmtBytes', () => {
  it('devuelve — para 0 o nulo', () => {
    expect(fmtBytes(0)).toBe('—')
    expect(fmtBytes(null)).toBe('—')
    expect(fmtBytes(undefined)).toBe('—')
  })

  it('formatea B, KB y MB', () => {
    expect(fmtBytes(512)).toBe('512 B')
    expect(fmtBytes(2048)).toBe('2.0 KB')
    expect(fmtBytes(5 * 1024 * 1024)).toBe('5.00 MB')
  })
})

describe('analyze-format · errMessage (mapeo honesto de errores)', () => {
  it('413 → mensaje de archivo demasiado grande', () => {
    const msg = errMessage({ response: { status: 413 } })
    expect(msg).toMatch(/demasiado grande/i)
    expect(msg).toContain(`${MAX_FILE_MB} MB`)
  })

  it('ECONNABORTED → mensaje de timeout', () => {
    expect(errMessage({ code: 'ECONNABORTED' })).toMatch(/tardó demasiado/i)
  })

  it('mensaje con "timeout" → mensaje de timeout (caso "timeout of 15000ms exceeded")', () => {
    expect(errMessage({ message: 'timeout of 15000ms exceeded' })).toMatch(/tardó demasiado/i)
  })

  it('propaga el detail del backend cuando existe', () => {
    expect(errMessage({ response: { data: { detail: 'Tipo MIME no permitido' } } })).toBe('Tipo MIME no permitido')
  })

  it('cae al message genérico de axios', () => {
    expect(errMessage({ message: 'Network Error' })).toBe('Network Error')
  })

  it('fallback final cuando el error no trae nada útil', () => {
    expect(errMessage({})).toBe('No se pudo completar el análisis.')
  })
})
