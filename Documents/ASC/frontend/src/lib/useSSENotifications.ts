'use client'

/**
 * useSSENotifications — P21-F4
 *
 * Reusable hook for the PANL real-time SSE event stream.
 * Connects to GET /api/v1/notifications/stream?token=<jwt>
 * and delivers typed notification events to callers.
 *
 * Features:
 *  - Auto-reconnect on error (exponential backoff, max 30s)
 *  - Caller supplies an onEvent callback; hook handles lifecycle
 *  - Returns { connected, lastEvent, reconnectCount }
 *  - Cleans up EventSource on unmount
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { getAccessToken } from './auth'

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

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
const MAX_BACKOFF_MS = 30_000
const BASE_BACKOFF_MS = 1_000

export function useSSENotifications({ onEvent, enabled = true }: UseSSEOptions = {}): SSEState {
  const [state, setState] = useState<SSEState>({
    connected: false,
    lastEvent: null,
    reconnectCount: 0,
  })

  const esRef = useRef<EventSource | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectCountRef = useRef(0)
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  const connect = useCallback(() => {
    const token = getAccessToken()
    if (!token || !enabled) return

    const url = `${API_URL}/api/v1/notifications/stream?token=${encodeURIComponent(token)}`
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => {
      reconnectCountRef.current = 0
      setState(prev => ({ ...prev, connected: true, reconnectCount: 0 }))
    }

    es.onmessage = (e) => {
      try {
        const parsed: SSENotification = JSON.parse(e.data)
        setState(prev => ({ ...prev, lastEvent: parsed }))
        onEventRef.current?.(parsed)
      } catch {
        // Heartbeat comments (": heartbeat") are not message events; ignore parse errors
      }
    }

    es.onerror = () => {
      es.close()
      esRef.current = null
      setState(prev => ({ ...prev, connected: false }))

      // Exponential backoff
      const delay = Math.min(BASE_BACKOFF_MS * 2 ** reconnectCountRef.current, MAX_BACKOFF_MS)
      reconnectCountRef.current += 1
      setState(prev => ({ ...prev, reconnectCount: reconnectCountRef.current }))

      reconnectTimerRef.current = setTimeout(connect, delay)
    }
  }, [enabled])

  useEffect(() => {
    if (!enabled) return

    connect()

    return () => {
      esRef.current?.close()
      esRef.current = null
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
    }
  }, [connect, enabled])

  return state
}
