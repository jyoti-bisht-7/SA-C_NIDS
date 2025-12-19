
const fs = require('fs')
const path = require('path')
const express = require('express')
const cors = require('cors')
const https = require('https')
const http = require('http')
const { WebSocketServer } = require('ws')
const jwt = require('jsonwebtoken')
const rateLimit = require('express-rate-limit')
const morgan = require('morgan')
const { body, validationResult } = require('express-validator')
const axios = require('axios')
const Redis = require('ioredis')
const client = require('prom-client')
const cron = require('node-cron')

// --- Config ---
const PORT = process.env.PORT || 4000
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret'
const REQUIRE_MTLS = process.env.REQUIRE_MTLS === '1'
const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379'

const app = express()
app.use(cors())
app.use(express.json({ limit: '1mb' }))
app.use(morgan('combined'))

// --- DB module (assumed) ---
const dbModule = require('./db') // keep your existing DB wrapper

// --- Redis ---
const redis = new Redis(REDIS_URL)
redis.on('error', (e) => console.error('Redis error', e))

// --- Prometheus metrics ---
client.collectDefaultMetrics()
const agentEventsCounter = new client.Counter({
  name: 'nids_agent_events_received_total',
  help: 'Total events received from agents',
  labelNames: ['agent']
})

// Generic events counter (global)
const globalEvents = new client.Counter({ name: 'nids_events_total', help: 'Total events received' })

// --- Helpers ---
function verifyAgentAuth(req) {
  // If mTLS required, prefer cert
  if (REQUIRE_MTLS) {
    const cert = req.socket.getPeerCertificate && req.socket.getPeerCertificate()
    if (!cert || Object.keys(cert).length === 0) throw new Error('client certificate required')
    // Use CN as agent id if available
    return (cert.subject && cert.subject.CN) || 'mtls-agent'
  }
  const auth = req.headers['authorization']
  if (!auth) throw new Error('missing authorization')
  const parts = auth.split(' ')
  if (parts.length !== 2 || parts[0] !== 'Bearer') throw new Error('invalid authorization format')
  const token = parts[1]
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    return payload.agent_id || payload.sub || 'agent-unknown'
  } catch (e) {
    throw new Error('invalid token')
  }
}

// per-agent rate limiter: uses verifyAgentAuth to key by agent id; falls back to IP
const agentLimiter = rateLimit({
  windowMs: 1000,
  max: 200, // allow bursts per second per agent; tune as needed
  keyGenerator: (req) => {
    try { return verifyAgentAuth(req) } catch { return req.ip }
  },
  handler: (req, res) => res.status(429).json({ error: 'rate limit' })
})

// In-memory fallback queue when Redis is down
const localQueue = []

async function enqueueEvent(evt) {
  globalEvents.inc()
  if (!evt) return
  try {
    await redis.lpush('events', JSON.stringify(evt))
  } catch (e) {
    console.error('Redis push failed, buffering locally', e.message || e)
    localQueue.push(evt)
  }
}

// flush local queue periodically
setInterval(async () => {
  if (localQueue.length === 0) return
  const batch = localQueue.splice(0, 100)
  try {
    await redis.lpush('events', ...batch.map(e => JSON.stringify(e)))
    console.log(`Flushed ${batch.length} buffered events`)    
  } catch (e) {
    console.error('Redis still unavailable, re-buffering', e.message || e)
    // put back front (simple strategy)
    localQueue.unshift(...batch)
  }
}, 5000)

// --- Basic simulated signatures (fallback) ---
const fallbackSignatures = [
  { id: 1, name: 'SYN-Flood', desc: 'Multiple SYN to same target port', active: 1 },
  { id: 2, name: 'Port-Scan', desc: 'Sequential port probes', active: 1 },
  { id: 3, name: 'Brute-Auth', desc: 'Many failed auth attempts', active: 1 }
]

// --- Simple global rate limit for non-agent endpoints ---
app.use(rateLimit({ windowMs: 1000, max: 100 }))

// --- Public endpoints ---
app.get('/api/summary', (req, res) => {
  res.json({ activeConnections: Math.floor(Math.random()*200)+50, alerts24h: Math.floor(Math.random()*10), suspiciousFlows: Math.floor(Math.random()*8) })
})

app.get('/api/alerts', (req, res) => {
  dbModule.listAlerts((err, rows) => {
    if (err) return res.status(500).json({ error: 'db' })
    try {
      // rows are ordered by time DESC in db module; return only one alert per type (most recent)
      const seen = new Set()
      const filtered = []
      for (const r of rows) {
        const t = r.type || 'unknown'
        if (!seen.has(t)) {
          seen.add(t)
          filtered.push(r)
        }
      }
      return res.json(filtered)
    } catch (e) {
      console.error('filtering alerts failed', e)
      return res.json(rows)
    }
  })
})

app.get('/api/audit', (req, res) => {
  dbModule.listAudit((err, rows) => {
    if (err) {
      console.error('db listAudit error', err)
      return res.json([
        { time: '10:01', message: 'Agent started, listening on eth0' },
        { time: '10:15', message: 'Loaded 3 signature rules' },
        { time: '12:21', message: 'Alert created: SYN-Flood from 10.1.1.5' }
      ])
    }
    res.json(rows)
  })
})

// signatures listing
app.get('/api/signatures', (req, res) => {
  dbModule.listSignatures((err, rows) => {
    if (err) return res.json(fallbackSignatures)
    res.json(rows)
  })
})

// agent config pull - agents call this to get active signatures and settings
app.get('/api/agent/config', (req, res) => {
  try {
    const agentId = verifyAgentAuth(req)
    dbModule.listSignatures((err, rows) => {
      const sigs = err ? fallbackSignatures : rows
      const active = sigs.filter(s => s.active !== 0).map(s => s.name || s)
      res.json({ agent: agentId, sampling_interval_ms: 500, active_signatures: active })
    })
  } catch (e) {
    return res.status(401).json({ error: e.message })
  }
})

// --- Agent ingest endpoint ---
app.post('/api/agent/event', agentLimiter, requireClientCertIfNeeded, [
  body('src').isString(),
  body('dst').isString(),
  body('proto').optional().isIn(['TCP','UDP','ICMP']),
  body('size').optional().isInt({ min: 1 }),
  body('time').optional().isString(),
  body('pid').optional().isInt(),
  body('proc_name').optional().isString()
], async (req, res) => {
  try {
    const agentId = verifyAgentAuth(req)
    const errors = validationResult(req)
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() })

    const evt = Object.assign({ agent: agentId, time: new Date().toISOString() }, req.body)

    // instrument metric
    agentEventsCounter.labels(agentId).inc()

    // enqueue for processing
    await enqueueEvent({ type: 'event', data: evt })

    // broadcast to WS clients
    broadcastWS({ type: 'packet', data: evt })

      // server-side signature scan: create alerts for matched signatures
      try { scanEventForSignatures(evt) } catch (e) { console.error('sig scan failed', e) }

    return res.status(202).json({ status: 'accepted', agent: agentId })
  } catch (e) {
    return res.status(401).json({ error: e.message })
  }
})

// --- Accept alerts posted by lightweight agents or scripts ---
async function handleIncomingAlert(req, res) {
  try {
    const body = req.body || {}
    const alert = {
      id: body.id || `alert-${Date.now()}`,
      type: body.name || body.type || 'alert',
      severity: body.severity || 'medium',
      description: body.description || body.desc || '',
      time: body.time || new Date().toISOString(),
      src: body.src_ip || body.src || body.srcIp || '',
      dst: body.dst_ip || body.dst || body.dstIp || '',
    }

    // persist
    dbModule.insertAlert(alert, (err) => {
      if (err) {
        console.error('insertAlert error', err)
        return res.status(500).json({ error: 'db' })
      }

      // audit log
      dbModule.insertAudit(`Alert received: ${alert.type} ${alert.src} -> ${alert.dst}`)

      // broadcast to websocket clients (live dashboard)
      try { broadcastWS({ type: 'alert', data: alert }) } catch (e) {}

      return res.status(201).json({ status: 'accepted', alert: alert })
    })
  } catch (e) {
    return res.status(400).json({ error: e.message })
  }
}

// Accept alerts at both root and /api/ prefix to be compatible with various agents
app.post('/alerts', handleIncomingAlert)
app.post('/api/alerts', handleIncomingAlert)

// helper: require mTLS only if configured
function requireClientCertIfNeeded(req, res, next) {
  if (!REQUIRE_MTLS) return next()
  const cert = req.socket.getPeerCertificate && req.socket.getPeerCertificate()
  if (!cert || Object.keys(cert).length === 0) return res.status(401).json({ error: 'client certificate required' })
  return next()
}

// --- WS server and helpers ---
let server
const certDir = path.join(__dirname, 'certs')
if (fs.existsSync(path.join(certDir, 'server.key')) && fs.existsSync(path.join(certDir, 'server.crt'))) {
  const key = fs.readFileSync(path.join(certDir, 'server.key'))
  const cert = fs.readFileSync(path.join(certDir, 'server.crt'))
  const ca = fs.existsSync(path.join(certDir, 'ca.crt')) ? fs.readFileSync(path.join(certDir, 'ca.crt')) : undefined
  const httpsOpts = { key, cert }
  if (ca) httpsOpts.ca = ca
  if (REQUIRE_MTLS) {
    httpsOpts.requestCert = true
    httpsOpts.rejectUnauthorized = false
  }
  server = https.createServer(httpsOpts, app).listen(PORT, () => console.log(`Backend REST API listening on https://localhost:${PORT}`))
} else {
  server = http.createServer(app).listen(PORT, () => console.log(`Backend REST API listening on http://localhost:${PORT} (no TLS)`))
}

const wss = new WebSocketServer({ server, path: '/ws' })

// --- Load signature rules from repo signatures/signatures.json if available ---
let localSignatures = []
try {
  const sigPath = path.join(__dirname, '..', 'signatures', 'signatures.json')
  if (fs.existsSync(sigPath)) {
    localSignatures = JSON.parse(fs.readFileSync(sigPath, 'utf8'))
    console.log(`Loaded ${localSignatures.length} signature rules from signatures/signatures.json`)
  }
} catch (e) {
  console.warn('Could not load local signatures.json', e.message || e)
}

// Ensure these local signature rules exist in the DB (insert only if missing)
if (localSignatures && localSignatures.length > 0) {
  try {
    dbModule.listSignatures((err, rows) => {
      if (err) {
        console.error('Could not list signatures for seeding:', err)
        return
      }
      const existing = new Set((rows || []).map(r => (r.name || '').toLowerCase()))
      localSignatures.forEach((s) => {
        const name = (s.name || s.id || '').toString()
        if (!name) return
        if (!existing.has(name.toLowerCase())) {
          console.log('Seeding signature into DB:', name)
          dbModule.insertSignature({ name, desc: s.description || s.desc || '' }, (ie) => {
            if (ie) console.error('Failed to insert signature', name, ie)
          })
        }
      })
    })
  } catch (e) {
    console.error('Signature seeding error', e)
  }
}

function scanEventForSignatures(evt) {
  if (!evt) return
  try {
    const proc = (evt.proc_name || evt.proc || '') + ''
    const dst = (evt.dst || evt.dst_host || evt.host || '') + ''
    const qname = (evt.qname || evt.dns_qname || '') + ''
    const httpHost = (evt.http_host || '') + ''
    const sni = (evt.sni || '') + ''
    const hostCandidate = `${dst} ${qname} ${httpHost} ${sni}`.toLowerCase()

    localSignatures.forEach((s) => {
      const pats = (s.patterns || []).map(p => p.toLowerCase())
      let matched = false
      if (s.type === 'process' || s.type === 'hybrid') {
        for (const p of pats) {
          if (proc && proc.toLowerCase().includes(p)) { matched = true; break }
        }
      }
      if (!matched && (s.type === 'domain' || s.type === 'hybrid')) {
        for (const p of pats) {
          if (hostCandidate && (hostCandidate.includes(p) || hostCandidate.endsWith(p))) { matched = true; break }
        }
      }

      if (matched) {
        const alert = {
          id: s.id || `sig-${s.name}-${Date.now()}`,
          type: s.name || (s.id || 'signature'),
          severity: s.severity || 'medium',
          description: s.description || `Signature ${s.name} matched for ${proc || dst}`,
          time: new Date().toISOString(),
          src: evt.src || evt.src_ip || '',
          dst: evt.dst || evt.dst_ip || dst || '',
        }
        dbModule.insertAlert(alert, (err) => {
          if (err) console.error('insertAlert (sig) failed', err)
        })
        try { broadcastWS({ type: 'alert', data: alert }) } catch (e) {}
      }
    })
  } catch (e) {
    console.error('scanEventForSignatures error', e)
  }
}

function broadcastWS(msg) {
  const str = JSON.stringify(msg)
  wss.clients.forEach((client) => {
    try {
      if (client.readyState === client.OPEN) client.send(str)
    } catch (e) {}
  })
}

// connection handling
wss.on('connection', (ws, req) => {
  // simple auth support via ?token=... or Sec-WebSocket-Protocol
  try {
    const url = new URL(req.url, `http://${req.headers.host}`)
    const token = url.searchParams.get('token') || (req.headers['sec-websocket-protocol'] || '').split(',')[0]
    if (!token && REQUIRE_MTLS) {
      const cert = req.socket.getPeerCertificate && req.socket.getPeerCertificate()
      if (!cert || Object.keys(cert).length === 0) { ws.close(1008, 'client certificate required'); return }
    }
    if (token) jwt.verify(token, JWT_SECRET)
  } catch (e) { ws.close(1008, 'invalid token'); return }

  console.log('WS client connected')
  const iv = setInterval(() => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ type: 'heartbeat', time: new Date().toISOString() }))
  }, 10000)

  ws.on('message', (msg) => { console.log('WS received:', msg.toString()) })
  ws.on('close', () => { clearInterval(iv); console.log('WS client disconnected') })
})

// --- Metrics endpoint ---
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', client.register.contentType)
  res.end(await client.register.metrics())
})

// --- Health ---
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }))

// --- Retention job ---
cron.schedule('0 2 * * *', async () => {
  console.log('Running retention job')
  try {
    const removed = await dbModule.retentionJob(process.env.RETENTION_DAYS ? Number(process.env.RETENTION_DAYS) : 30)
    console.log(`Retention job removed ${removed || 0} old rows`)  
  } catch (e) {
    console.error('Retention job failed', e)
  }
})

console.log('server_improved.js loaded')

// --- Export for tests if needed ---
module.exports = { app, server, enqueueEvent, broadcastWS }
