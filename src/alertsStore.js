// Simple in-memory alerts pub/sub for UI components
const subscribers = new Set()

export function subscribeAlerts(cb) {
  subscribers.add(cb)
  return () => subscribers.delete(cb)
}

export function pushAlert(alert) {
  const now = new Date()
  const a = {
    id: alert.id || `sig-${now.getTime()}`,
    type: alert.type || alert.signature || 'Signature Match',
    severity: alert.severity || 'medium',
    description: alert.description || alert.message || '',
    time: alert.time || now.toLocaleTimeString(),
    src: alert.src || alert.src_ip || 'unknown',
    dst: alert.dst || alert.dst_ip || alert.dst_host || 'unknown',
    signature: alert.signature || null,
    meta: alert.meta || {},
  }
  for (const cb of subscribers) {
    try { cb(a) } catch (e) { console.error('alert subscriber failed', e) }
  }
}

export default { subscribeAlerts, pushAlert }
