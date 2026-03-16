import axios from 'axios'

const BASE = import.meta.env.VITE_API_URL || '/api'

const api = axios.create({ baseURL: BASE, timeout: 30000 })

export const analyseInput = (payload) => api.post('/analyse', payload).then(r => r.data)
export const getIncidents = (page = 1, severity) =>
  api.get('/incidents', { params: { page, limit: 20, severity } }).then(r => r.data)
export const getIncident  = (id) => api.get(`/incidents/${id}`).then(r => r.data)
export const submitFeedback = (id, is_false_positive, notes) =>
  api.post(`/feedback/${id}`, { is_false_positive, notes }).then(r => r.data)
export const getHealth = () => api.get('/health').then(r => r.data)
export const ingestFile = (file) => {
  const fd = new FormData()
  fd.append('file', file)
  return api.post('/ingest/file', fd, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data)
}

export const createWebSocket = (onMessage, onClose) => {
  const wsBase = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000').replace(/\/+$/, '')
  const ws = new WebSocket(`${wsBase}/ws/live`)
  ws.onmessage = (e) => { try { onMessage(JSON.parse(e.data)) } catch {} }
  ws.onclose   = () => onClose && onClose()
  ws.onerror   = () => ws.close()
  return ws
}
