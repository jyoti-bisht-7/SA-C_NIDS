import { getCached, setCached } from './dataCache'

const subscribers = new Set()

export function subscribeAudit(cb) {
  subscribers.add(cb)
  return () => subscribers.delete(cb)
}

export function pushAudit(entry) {
  const time = entry.time || new Date().toLocaleTimeString()
  const message = entry.message || entry.msg || ''
  const row = { time, message }

  // Update cache
  try {
    const cached = getCached('audit') || []
    const next = [row, ...cached].slice(0, 200)
    try { setCached('audit', next) } catch {}
  } catch (e) {
    // ignore cache errors
  }

  // Notify subscribers
  for (const cb of subscribers) {
    try { cb(row) } catch (e) { console.error('audit subscriber failed', e) }
  }
}

export default { subscribeAudit, pushAudit }
