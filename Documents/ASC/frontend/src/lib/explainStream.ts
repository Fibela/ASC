// Explainer en vivo (S102/S109) — consumidor SSE por fetch (POST + JWT en HEADER,
// no en la URL: más seguro que EventSource). La ANTHROPIC_API_KEY vive SOLO en el
// backend; el frontend nunca la ve — solo consume el stream ya renderizado.
import { env } from './env'
import { getAccessToken } from './auth'

export interface ExplainCallbacks {
  onMeta?: (m: { alert_id?: string; profile?: string }) => void
  onDelta?: (text: string) => void
  onDone?: () => void
  onError?: (detail: string) => void
}

/**
 * Parsea un buffer con tramas SSE completas (separadas por \n\n), despacha cada
 * evento a los callbacks y devuelve el remanente incompleto. Función PURA (testeable).
 */
export function parseSSEChunk(buffer: string, cb: ExplainCallbacks): string {
  const frames = buffer.split('\n\n')
  const leftover = frames.pop() ?? ''
  for (const frame of frames) {
    if (!frame.trim()) continue
    let event = 'message'
    let data = ''
    for (const line of frame.split('\n')) {
      if (line.startsWith('event:')) event = line.slice(6).trim()
      else if (line.startsWith('data:')) data = line.slice(5).trim()
    }
    let parsed: Record<string, unknown> = {}
    try {
      parsed = data ? JSON.parse(data) : {}
    } catch {
      continue // trama corrupta → se ignora, no se rompe el stream
    }
    if (event === 'meta') cb.onMeta?.(parsed as { alert_id?: string; profile?: string })
    else if (event === 'delta') {
      const t = (parsed as { text?: string }).text
      if (t) cb.onDelta?.(t)
    } else if (event === 'done') cb.onDone?.()
    else if (event === 'error') cb.onError?.((parsed as { detail?: string }).detail ?? 'Error')
  }
  return leftover
}

/** Abre el stream de explicación de una alerta y despacha los eventos a los callbacks. */
export async function streamExplanation(
  alertId: string,
  cb: ExplainCallbacks,
  signal?: AbortSignal,
): Promise<void> {
  const token = getAccessToken()
  const resp = await fetch(
    `${env.API_URL}/api/v1/alerts/${encodeURIComponent(alertId)}/explain`,
    { method: 'POST', headers: { Authorization: `Bearer ${token ?? ''}` }, signal },
  )
  if (resp.status === 503) {
    cb.onError?.('El explainer no está configurado (falta ANTHROPIC_API_KEY en el servidor).')
    return
  }
  if (!resp.ok || !resp.body) {
    cb.onError?.(`No se pudo obtener la explicación (HTTP ${resp.status}).`)
    return
  }
  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    buffer = parseSSEChunk(buffer, cb)
  }
  if (buffer.trim()) parseSSEChunk(buffer + '\n\n', cb)
}
