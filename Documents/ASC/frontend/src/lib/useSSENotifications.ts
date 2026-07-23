'use client'

/**
 * useSSENotifications — P21-F4 · endurecido en S111.1
 *
 * Stream SSE en tiempo real de PANL. Consume GET /api/v1/notifications/stream
 * vía `fetch` con el JWT en el HEADER `Authorization` (NO en la URL) — cerrando
 * la fuga de token en la URL (S111.1: los tokens en la URL se filtran a logs,
 * historial y proxies). EventSource no permite headers; por eso usamos fetch+stream.
 *
 * Features:
 *  - Auto-reconnect con backoff exponencial (máx 30s)
 *  - onEvent callback; el hook maneja el ciclo de vida
 *  - Devuelve { connected, lastEvent, reconnectCount }
 *  - Aborta el fetch en unmount
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { getAccessToken } from './auth'
import { env } from './env'

export interface SSENotification {
  type: string
  action_id?: string
  action_type?: string
  target?: string
  severity?: string
  status?: string
  initiated_by?: string
  approved_by?: string
  message?: string
  ts?: string
  [key: string]: unknown
}

interface UseSSEOptions {
  onEvent?: (event: SSENotification) => void
  enabled?: boolean
}

interface SSEState {
  connected: boolean
  lastEvent: SSENotification | null
  reconnectCount: number
}

const MAX_BACKOFF_MS = 30_000
const BASE_BACKOFF_MS = 1_000

export function useSSENotifications({ onEvent, enabled = true }: UseSSEOptions = {}): SSEState {
  const [state, setState] = useState<SSEState>({
    connected: false,
    lastEvent: null,
    reconnectCount: 0,
  })

  const abortRef = useRef<AbortController | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectCountRef = useRef(0)
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  const connect = useCallback(async () => {
    const token = getAccessToken()
    if (!token || !enabled) return

    const ac = new AbortController()
    abortRef.current = ac

    const scheduleReconnect = () => {
      setState(prev => ({ ...prev, connected: false }))
      const delay = Math.min(BASE_BACKOFF_MS * 2 ** reconnectCountRef.current, MAX_BACKOFF_MS)
      reconnectCountRef.current += 1
      setState(prev => ({ ...prev, reconnectCount: reconnectCountRef.current }))
      reconnectTimerRef.current = setTimeout(() => { void connect() }, delay)
    }

    try {
      const resp = await fetch(`${env.API_URL}/api/v1/notifications/stream`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
        signal: ac.signal,
      })
      if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status}`)

      reconnectCountRef.current = 0
      setState(prev => ({ ...prev, connected: true, reconnectCount: 0 }))

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const frames = buffer.split('\n\n')
        buffer = frames.pop() ?? ''
        for (const frame of frames) {
          // Solo líneas 'data:'; se ignoran comentarios (': heartbeat') y 'event:'.
          const dataLines = frame
            .split('\n')
            .filter(l => l.startsWith('data:'))
            .map(l => l.slice(5).trim())
          if (dataLines.length === 0) continue
          try {
            const parsed: SSENotification = JSON.parse(dataLines.join('\n'))
            setState(prev => ({ ...prev, lastEvent: parsed }))
            onEventRef.current?.(parsed)
          } catch {
            // heartbeat / no-JSON → ignorar
          }
        }
      }
      // El stream terminó limpio → reconectar.
      scheduleReconnect()
    } catch (e) {
      if ((e as { name?: string })?.name === 'AbortError') return
      scheduleReconnect()
    }
  }, [enabled])

  useEffect(() => {
    if (!enabled) return
    void connect()
    return () => {
      abortRef.current?.abort()
      abortRef.current = null
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
    }
  }, [connect, enabled])

  return state
}
