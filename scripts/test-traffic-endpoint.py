#!/usr/bin/env python3
"""Validate the local integration fixture itself, with TLS verification enabled."""
import http.client
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
server = subprocess.Popen([sys.executable, str(ROOT / "scripts/traffic-endpoint.py")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    assert select.select([server.stdout], [], [], 5)[0], "Endpoint startup timeout"
    assert b'"ready": true' in server.stdout.readline(), "Endpoint failed"
    data = b"control-host"
    with socket.create_connection(("127.0.0.1", 18080), 2) as s:
        s.sendall(data)
        assert s.recv(1024) == data
    query = bytes.fromhex("123401000001000000000000") + b"\x04test\x07invalid\x00\x00\x01\x00\x01"
    def dns(response):
        assert response[:2] == query[:2] and response[2:4] == b"\x81\x83" and response[12:] == query[12:]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        for port, payload in [(18081, data), (1053, query)]:
            s.sendto(payload, ("127.0.0.1", port))
            response = s.recv(1024)
            if port == 1053:
                dns(response)
            else:
                assert response == payload
    with socket.create_connection(("127.0.0.1", 1053), 2) as s:
        s.sendall(len(query).to_bytes(2, "big") + query)
        stream = s.makefile("rb")
        size = int.from_bytes(stream.read(2), "big")
        dns(stream.read(size))
    tls = ssl.create_default_context(cafile=str(ROOT / "probe/src/main/assets/endpoint.crt"))
    with tls.wrap_socket(socket.create_connection(("127.0.0.1", 1853), 2), server_hostname="10.0.2.2") as s:
        s.sendall(len(query).to_bytes(2, "big") + query)
        stream = s.makefile("rb")
        size = int.from_bytes(stream.read(2), "big")
        dns(stream.read(size))
    with tls.wrap_socket(socket.create_connection(("127.0.0.1", 18443), 2), server_hostname="10.0.2.2") as s:
        s.sendall(f"POST /dns-query HTTP/1.1\r\nHost: 10.0.2.2\r\nContent-Type: application/dns-message\r\nContent-Length: {len(query)}\r\n\r\n".encode() + query)
        response = http.client.HTTPResponse(s)
        response.begin()
        assert response.status == 200
        dns(response.read())
    print("PASS: local TCP, UDP, DNS/UDP, DNS/TCP, certificate-verified DoT and DoH fixture controls")
finally:
    server.terminate()
    try:
        server.wait(5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()
