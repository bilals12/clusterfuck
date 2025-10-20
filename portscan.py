#!/usr/bin/env python3
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan(ip, port):
    try:
        s = socket.socket()
        s.settimeout(0.3)
        result = s.connect_ex((ip, port))
        s.close()
        return (port, result == 0)
    except:
        return (port, False)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: portscan.py <host> <port1> <port2> ...")
        sys.exit(1)

    host = sys.argv[1]
    ports = [int(p) for p in sys.argv[2:]]

    try:
        ip = socket.gethostbyname(host)
    except:
        print(f"DNS failed: {host}")
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(scan, ip, p): p for p in ports}
        for future in as_completed(futures, timeout=5):
            port, is_open = future.result()
            print(f"{port}:{'OPEN' if is_open else 'CLOSED'}")
