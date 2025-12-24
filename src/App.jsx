import React, { Suspense, lazy, useState, useEffect } from 'react'
import signatureEngine from './signatures/engine'
import { Routes, Route, NavLink, useNavigate } from 'react-router-dom'
import ErrorBoundary from './ErrorBoundary'

// Lazy load heavy components
const Dashboard = lazy(() => import('./components/Dashboard'))
const Alerts = lazy(() => import('./components/Alerts'))
const Signatures = lazy(() => import('./components/Signatures'))
const AuditLog = lazy(() => import('./components/AuditLog'))
const MLInsights = lazy(() => import('./components/MLInsights'))
const DemoTraffic = lazy(() => import('./components/DemoTraffic'))

export default function App() {
  const [mode, setMode] = useState('realtime')
  const [serverUp, setServerUp] = useState(true)
  const [serverMsg, setServerMsg] = useState('')
  const navigate = useNavigate()
  useEffect(() => { signatureEngine.initSignatureEngine() }, [])

  // Lightweight backend health check via WebSocket probes used by the app
  useEffect(() => {
    let mounted = true
    const bases = ['ws://localhost:4000/ws', 'ws://127.0.0.1:4000/ws']
    let connected = false
    let sockets = []

    async function probe() {
      for (const url of bases) {
        try {
          const ws = new WebSocket(url)
          sockets.push(ws)
          const to = setTimeout(() => {
            try { ws.close() } catch (e) {}
          }, 800)
          ws.addEventListener('open', () => {
            clearTimeout(to)
            connected = true
            if (!mounted) return
            setServerUp(true)
            setServerMsg('Backend connected')
            // close all probes
            sockets.forEach(s => { try { s.close() } catch (e) {} })
          })
          ws.addEventListener('error', () => {})
        } catch (e) {}
      }

      // if none connected after short delay mark as down
      setTimeout(() => {
        if (!mounted) return
        if (!connected) {
          setServerUp(false)
          setServerMsg('Backend offline — navigation disabled')
        }
      }, 900)
    }

    probe()

    return () => {
      mounted = false
      sockets.forEach(s => { try { s.close() } catch (e) {} })
    }
  }, [])

  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <h2>NIDS Dashboard</h2>
        <nav>
          {/* prevent navigation when server is down */}
          <NavLink
            to="/"
            end
            className={({ isActive }) => (isActive ? 'active' : '')}
            onClick={(e) => { if (!serverUp) { e.preventDefault(); alert(serverMsg) } }}
          >
            Dashboard
          </NavLink>
          <NavLink
            to="/alerts"
            className={({ isActive }) => (isActive ? 'active' : '')}
            onClick={(e) => { if (!serverUp) { e.preventDefault(); alert(serverMsg) } }}
          >
            Alerts
          </NavLink>
          <NavLink
            to="/signatures"
            className={({ isActive }) => (isActive ? 'active' : '')}
            onClick={(e) => { if (!serverUp) { e.preventDefault(); alert(serverMsg) } }}
          >
            Signatures
          </NavLink>
          <NavLink
            to="/ml"
            className={({ isActive }) => (isActive ? 'active' : '')}
            onClick={(e) => { if (!serverUp) { e.preventDefault(); alert(serverMsg) } }}
          >
            ML Insights
          </NavLink>
          <NavLink
            to="/audit"
            className={({ isActive }) => (isActive ? 'active' : '')}
            onClick={(e) => { if (!serverUp) { e.preventDefault(); alert(serverMsg) } }}
          >
            Audit Log
          </NavLink>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="main">
        {!serverUp && (
          <div style={{ background: '#fff4e6', padding: 8, borderBottom: '1px solid #ffdcb1' }}>
            <strong>Offline:</strong> Backend appears to be offline. Navigation is disabled until it is available.
          </div>
        )}
        <ErrorBoundary>
          <Suspense fallback={<div style={{ textAlign: 'center', marginTop: 40, color: '#94a3b8' }}>Loading...</div>}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/demo" element={<DemoTraffic />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/signatures" element={<Signatures />} />
              <Route path="/ml" element={<MLInsights />} />
              <Route path="/audit" element={<AuditLog />} />
              <Route path="*" element={<div style={{ textAlign: 'center', marginTop: 40 }}>404 — Page Not Found</div>} />
            </Routes>
          </Suspense>
        </ErrorBoundary>
      </main>

      {/* Bottom-left mode buttons (Realtime / Demo) */}
      <div className="mode-toggle">
        <button
          className={mode === 'realtime' ? 'active' : ''}
          onClick={() => { setMode('realtime'); navigate('/') }}
          title="Switch to realtime mode"
        >
          Realtime
        </button>
      </div>
    </div>
  )
}
