// Lightweight hybrid API — uses live backend if available, else mock data
const API_BASE = 'https://localhost:8443/api'
// Try common local dev websocket endpoints (include backend on port 4000)
const WS_BASES = [
  'ws://localhost:4000/ws',
  'ws://127.0.0.1:4000/ws',
  'wss://localhost:8443/ws',
  'ws://localhost:8443/ws',
]

const random = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min

export const signatures = [
  { id: 1, name: 'SYN-Flood', desc: 'Multiple SYN to same target port' },
  { id: 2, name: 'Port-Scan', desc: 'Sequential port probes' },
  { id: 3, name: 'Brute-Auth', desc: 'Many failed auth attempts' },
]

// ---- SUMMARY ----
export async function fetchSummary() {
  try {
    const r = await fetch(`${API_BASE}/summary`)
    if (r.ok) return await r.json()
  } catch (e) {}

  // fallback mock
  return new Promise((res) =>
    setTimeout(
      () =>
        res({
          activeConnections: random(80, 240),
          alerts24h: random(0, 12),
          suspiciousFlows: random(0, 6),
        }),
      300
    )
  )
}

// ---- ALERTS ----
export async function fetchAlerts() {
  try {
    const r = await fetch(`${API_BASE}/alerts`)
    if (r.ok) return await r.json()
  } catch (e) {}

  return new Promise((res) =>
    setTimeout(
      () =>
        res([
          {
            id: 'a1',
            type: 'DDoS',
            severity: 'high',
            description: 'High SYN rate',
            time: new Date().toLocaleTimeString(),
            src: '10.1.1.5',
            dst: '10.0.0.10',
          },
          {
            id: 'a2',
            type: 'Port-Scan',
            severity: 'medium',
            description: 'Multiple ports probed',
            time: new Date().toLocaleTimeString(),
            src: '192.168.1.50',
            dst: '10.0.0.10',
          },
        ]),
      400
    )
  )
}

// ---- AUDIT LOG ----
export async function fetchAudit() {
  try {
    const r = await fetch(`${API_BASE}/audit`)
    if (r.ok) return await r.json()
  } catch (e) {}

  return new Promise((res) =>
    setTimeout(
      () =>
        res([
          { time: '10:01', message: 'Agent started, listening on eth0' },
          { time: '10:15', message: 'Loaded 3 signature rules' },
          { time: '12:21', message: 'Alert created: SYN-Flood from 10.1.1.5' },
        ]),
      200
    )
  )
}

// ---- ML INSIGHTS ----
export async function fetchMLSeries() {
  try {
    const r = await fetch(`${API_BASE}/ml`)
    if (r.ok) return await r.json()
  } catch (e) {}

  const timestamps = []
  const scores = []
  const topAnomalies = []
  for (let i = 0; i < 20; i++) {
    timestamps.push(`${i}:00`)
    const s = Math.random() * 0.8
    scores.push(Number(s.toFixed(3)))
    if (s > 0.6)
      topAnomalies.push({
        time: `${i}:00`,
        score: Number(s.toFixed(3)),
        note: 'Unusual flow volume',
      })
  }

  return new Promise((res) =>
    setTimeout(() => res({ timestamps, scores, topAnomalies }), 300)
  )
}

// ---- PACKET STREAM ----
export function streamPackets(cb) {
  let connected = false
  let ws = null

  for (const url of WS_BASES) {
    try {
      ws = new WebSocket(url)
    } catch (e) {
      ws = null
    }
    if (!ws) continue

    const onOpen = () => {
      connected = true
      console.log('✅ Connected to backend WS:', url)
      ws.removeEventListener('open', onOpen)
    }
    ws.addEventListener('open', onOpen)

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'packet') cb(msg.data)
        if (msg.type === 'alert')
          cb({ ...msg.data, alert: msg.data.type })
      } catch (e) {}
    }

    ws.onclose = () => {
      if (connected) console.warn('⚠️ WS closed, switching to mock mode')
    }

    const timeout = setTimeout(() => {
      if (!connected) {
        try {
          ws.close()
        } catch (e) {}
        ws = null
      }
    }, 800)

    if (connected) {
      clearTimeout(timeout)
      return () => ws && ws.close()
    }
  }

  // ---- fallback mock packet stream ----
  console.log('🌐 Using mock packet stream')
  let mounted = true
  const interval = setInterval(() => {
    if (!mounted) return
    const pkt = {
      time: new Date().toLocaleTimeString(),
      src: `192.168.1.${random(2, 254)}`,
      dst: `10.0.0.${random(2, 254)}`,
      proto: Math.random() > 0.7 ? 'UDP' : 'TCP',
      size: random(40, 1500),
      alert: Math.random() > 0.985 ? 'Potential SYN-Flood' : null,
    }
    cb(pkt)
  }, 800)

  return () => {
    mounted = false
    clearInterval(interval)
  }
}
