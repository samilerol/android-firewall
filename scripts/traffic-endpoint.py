#!/usr/bin/env python3
"""Controlled emulator-only echo and DNS/TLS endpoints; no upstream requests."""
import argparse
import http.server
import json
from pathlib import Path
import signal
import socketserver
import socket
import ssl
import threading
import time

ROOT = Path(__file__).resolve().parent.parent

def record(kind, data):
    print(json.dumps({"time": time.time(), "kind": kind, "bytes": len(data), "payloadHex": data.hex()}), flush=True)

def dns_response(data):
    if len(data) < 12:
        raise ValueError("Truncated DNS")
    return data[:2] + bytes([0x81, 0x83]) + data[4:6] + bytes(6) + data[12:]

def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError()
        data.extend(chunk)
    return bytes(data)

class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(120)  # bounded hold across VPN startup for lifecycle tests
        while True:
            try:
                data = self.request.recv(1024)
            except (TimeoutError, ConnectionError):
                return
            if not data:
                return
            record("tcp", data)
            self.request.sendall(data)

class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        kind = "dns" if self.server.server_address[1] == 1053 else "udp"
        record(kind, data)
        sock.sendto(dns_response(data) if kind == "dns" else data, self.client_address)

class DoT(socketserver.StreamRequestHandler):
    kind = "dot"
    def handle(self):
        self.request.settimeout(3)
        size = int.from_bytes(read_exact(self.rfile, 2), "big")
        if not 12 <= size <= 1024:
            return
        data = read_exact(self.rfile, size)
        record(self.kind, data)
        reply = dns_response(data)
        self.wfile.write(len(reply).to_bytes(2, "big") + reply)

class DNSTCP(DoT):
    kind = "dns-tcp"

class DoH(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.connection.settimeout(3)
        size = int(self.headers.get("Content-Length", "0"))
        if self.path != "/dns-query" or self.headers.get("Content-Type") != "application/dns-message" or not 12 <= size <= 1024:
            self.send_error(400)
            return
        data = read_exact(self.rfile, size)
        record("doh", data)
        reply = dns_response(data)
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)
    def log_message(self, *_):
        pass

class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

class TCP6Server(TCPServer):
    address_family = socket.AF_INET6

class UDP6Server(UDPServer):
    address_family = socket.AF_INET6

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1", help="Emulator host loopback only by default")
    parser.add_argument("--ipv6", action="store_true", help="Also bind controlled IPv6 host loopback")
    args = parser.parse_args()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(ROOT / "probe/src/main/assets/endpoint.crt", ROOT / "scripts/fixtures/endpoint.key")
    servers = []
    endpoints = [
        (TCPServer, 18080, Echo, False), (UDPServer, 18081, UDP, False),
        (UDPServer, 1053, UDP, False), (TCPServer, 1053, DNSTCP, False), (TCPServer, 1853, DoT, True), (TCPServer, 18443, DoH, True)
    ]
    configurations = [(kind, args.bind, port, handler, encrypted) for kind, port, handler, encrypted in endpoints]
    if args.ipv6:
        configurations += [(TCP6Server if kind is TCPServer else UDP6Server, "::1", port, handler, encrypted)
                           for kind, port, handler, encrypted in endpoints]
    for server_type, bind, port, handler, encrypted in configurations:
        server = server_type((bind, port), handler)
        if encrypted:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(json.dumps({"ready": True, "bind": args.bind}), flush=True)
    signal.pause()
