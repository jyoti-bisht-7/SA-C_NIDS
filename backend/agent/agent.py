"""
Simple agent demo (Python) — captures packets (requires scapy) and forwards events to backend.

This is a demo. Run with:

# using mTLS
python agent.py --mtls --backend https://localhost:4000

# using JWT
python agent.py --jwt-token <token> --backend http://localhost:4000

Requires: pip install scapy requests
"""
import argparse
import json
import threading
import time
import requests
import psutil
from scapy.all import sniff, IP, TCP, UDP


def send_event(url, data, mtls=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        if mtls:
            r = requests.post(url + '/api/agent/event', json=data, headers=headers, cert=(mtls['cert'], mtls['key']), verify=mtls.get('ca', True))
        else:
            r = requests.post(url + '/api/agent/event', json=data, headers=headers)
        print('sent', r.status_code)
    except Exception as e:
        print('error sending event', e)


def packet_handler(pkt, args, backend_url, mtls, token):
    if IP in pkt:
        ip = pkt[IP]
        proto = 'TCP' if TCP in pkt else ('UDP' if UDP in pkt else str(ip.proto))
        src_port = pkt.sport if hasattr(pkt, 'sport') else None
        dst_port = pkt.dport if hasattr(pkt, 'dport') else None
        data = {
            'time': time.strftime('%H:%M:%S'),
            'src': ip.src,
            'src_port': src_port,
            'dst': ip.dst,
            'dst_port': dst_port,
            'proto': proto,
            'size': len(pkt)
        }

        # Try to attribute to a local process using psutil (best-effort, requires privileges)
        try:
            now = time.time()
            # cached small window of connections to avoid heavy syscall on every packet
            if not hasattr(packet_handler, '_cache'):
                packet_handler._cache = {'ts': 0, 'conns': []}
            if now - packet_handler._cache['ts'] > 1.0:
                # refresh connection table
                try:
                    packet_handler._cache['conns'] = psutil.net_connections(kind='inet')
                except Exception:
                    packet_handler._cache['conns'] = []
                packet_handler._cache['ts'] = now

            matched = None
            for c in packet_handler._cache['conns']:
                # c.laddr and c.raddr are tuples (ip, port) when present
                try:
                    laddr = (c.laddr.ip, c.laddr.port) if hasattr(c, 'laddr') and c.laddr else (None, None)
                except Exception:
                    laddr = (None, None)
                try:
                    raddr = (c.raddr.ip, c.raddr.port) if hasattr(c, 'raddr') and c.raddr else (None, None)
                except Exception:
                    raddr = (None, None)

                # match either direction
                if (laddr[0] == ip.src and laddr[1] == src_port and raddr[0] == ip.dst and raddr[1] == dst_port) or (
                        laddr[0] == ip.dst and laddr[1] == dst_port and raddr[0] == ip.src and raddr[1] == src_port):
                    matched = c
                    break

            if matched and matched.pid:
                data['pid'] = matched.pid
                try:
                    p = psutil.Process(matched.pid)
                    data['proc_name'] = p.name()
                except Exception:
                    data['proc_name'] = None
        except Exception:
            # silently ignore attribution failures
            pass

        # 🟩 ADD THIS LINE (pretty print to terminal)
        print(json.dumps(data, indent=2))

        threading.Thread(target=send_event, args=(backend_url, data, mtls, token)).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', required=True)
    parser.add_argument('--mtls', action='store_true')
    parser.add_argument('--mtls-cert')
    parser.add_argument('--mtls-key')
    parser.add_argument('--mtls-ca')
    parser.add_argument('--jwt-token')
    parser.add_argument('--iface', default=None)
    args = parser.parse_args()

    mtls = None
    if args.mtls:
        mtls = {'cert': args.mtls_cert or 'client.crt', 'key': args.mtls_key or 'client.key'}
        if args.mtls_ca:
            mtls['ca'] = args.mtls_ca

    print('Starting capture, backend:', args.backend)
    sniff(prn=lambda p: packet_handler(p, args, args.backend, mtls, args.jwt_token), iface=args.iface, store=0)


if __name__ == '__main__':
    main()
