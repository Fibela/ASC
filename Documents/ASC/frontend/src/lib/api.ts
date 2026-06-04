import axios from 'axios'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
})

// --- Metrics ---
export async function getSocMetrics(hours = 24) {
  const { data } = await api.get('/metrics/soc', { params: { hours } })
  return data
}

export async function getTimeline(hours = 24) {
  const { data } = await api.get('/metrics/timeline', { params: { hours } })
  return data
}

// --- Alerts ---
export async function getAlerts(params?: { severity?: string; status?: string; limit?: number }) {
  const { data } = await api.get('/alerts/', { params })
  return data
}

export async function getAlertStats() {
  const { data } = await api.get('/alerts/stats/summary')
  return data
}

export async function updateAlert(id: string, payload: Record<string, unknown>) {
  const { data } = await api.patch(`/alerts/${id}`, payload)
  return data
}

// --- Events ---
export async function getEvents(params?: { severity?: string; limit?: number }) {
  const { data } = await api.get('/events/', { params })
  return data
}

export async function ingestEvent(payload: Record<string, unknown>) {
  const { data } = await api.post('/events/ingest', payload)
  return data
}

// --- IoCs ---
export async function getIoCs(params?: { ioc_type?: string; limit?: number }) {
  const { data } = await api.get('/iocs/', { params })
  return data
}

export async function createIoC(payload: Record<string, unknown>) {
  const { data } = await api.post('/iocs/', payload)
  return data
}

// --- Analysis ---
export async function analyzeFile(file: File) {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post('/analyze/file', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return data
}

export async function analyzeDomain(domain: string) {
  const { data } = await api.post('/analyze/domain', null, { params: { domain } })
  return data
}

export async function analyzeIP(ip: string) {
  const { data } = await api.post('/analyze/ip', null, { params: { ip } })
  return data
}

// --- Neutralization ---
export async function executeAction(payload: Record<string, unknown>) {
  const { data } = await api.post('/neutralize/', payload)
  return data
}

export async function getNeutralizeHistory(limit = 20) {
  const { data } = await api.get('/neutralize/history', { params: { limit } })
  return data
}
