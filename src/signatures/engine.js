import { streamPackets } from '../mock/api'
import { pushAlert } from '../alertsStore'

const signatures = [
  { id: 'sig-brave', name: 'Brave Browser Launch', matchProc: /brave/i, severity: 'low' },
  { id: 'sig-whatsapp', name: 'WhatsApp Launch', matchProc: /whatsapp/i, severity: 'low' },
  { id: 'sig-youtube', name: 'YouTube Access', matchDst: /youtube\.com|youtu\.be/i, severity: 'low' },
  { id: 'sig-leetcode', name: 'LeetCode Access', matchDst: /leetcode\.com/i, severity: 'low' },
  { id: 'sig-gfg', name: 'GeeksforGeeks Access', matchDst: /geeksforgeeks\.org|geeksforgeeks\.com/i, severity: 'low' },
]

let initialized = false

export function initSignatureEngine() {
  if (initialized) return
  initialized = true

  // subscribe to live/mocked packet stream
  streamPackets((pkt) => {
    try { scanPacket(pkt) } catch (e) { console.error('signature scan fail', e) }
  })
}

export function scanPacket(pkt) {
  if (!pkt) return

  // check process name
  const proc = pkt.proc_name || pkt.proc || ''
  // collect candidate host fields that may be present in different agent outputs
  const dst = pkt.dst || pkt.dst_host || pkt.host || pkt.http_host || pkt.httpHost || pkt.hostname || ''

  // also check DNS/qname fields if present
  const dnsName = pkt.qname || pkt.dns_qname || pkt.dns_name || ''

  const hostCandidate = `${dst} ${dnsName}`

  signatures.forEach((s) => {
    let matched = false
    if (s.matchProc && proc && s.matchProc.test(proc)) matched = true
    if (s.matchDst && hostCandidate && s.matchDst.test(hostCandidate)) matched = true

    // Special-case: browser process + any destination => if the destination contains the site keyword,
    // mark as matched (helps when process is browser but dest uses IPs elsewhere)
    if (!matched && s.matchDst && proc && /chrome|brave|msedge|edge/i.test(proc) && hostCandidate && s.matchDst.test(hostCandidate)) matched = true

    if (matched) {
      pushAlert({
        id: `${s.id}-${Date.now()}`,
        type: s.name,
        signature: s.name,
        severity: s.severity,
        description: `Signature '${s.name}' matched for ${proc || dst}`,
        time: pkt.time || new Date().toLocaleTimeString(),
        src: pkt.src || pkt.src_ip,
        dst: dst || pkt.dst_ip,
        meta: { packet: pkt },
      })
    }
  })
}

export default { initSignatureEngine, scanPacket }
