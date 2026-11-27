#!/usr/bin/env python3
"""Verify public subscription bytes against the generated manifest."""
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.request import Request, urlopen

expected = json.loads(Path('status.json').read_text())
refs = [sys.argv[1], 'main']
for ref in refs:
    url = f'https://raw.githubusercontent.com/dijunux/adguard-privacy/{ref}/adguard.txt'
    for attempt in range(12):
        try:
            with urlopen(Request(url, headers={'Cache-Control': 'no-cache'}), timeout=30) as response:
                assert response.status == 200
                assert 'text/plain' in response.headers.get('Content-Type', '')
                body = response.read(4_100_001)
            assert len(body) == expected['bytes'], 'size differs (possibly CDN cache)'
            assert hashlib.sha256(body).hexdigest() == expected['sha256'], 'SHA-256 differs'
            assert body.startswith(b'! Title: AdGuard Privacy')
            print(f'PASS {url}: HTTP 200, {len(body)} bytes, SHA-256 {expected["sha256"]}')
            break
        except Exception as error:
            if attempt == 11:
                raise
            print(f'Waiting for public endpoint ({attempt + 1}/12): {error}')
            time.sleep(15)
