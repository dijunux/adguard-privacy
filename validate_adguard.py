#!/usr/bin/env python3
"""Load the candidate in official AdGuard Home; do not publish on failure."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen

VERSION = 'v1.0.0'
ARCHIVE = 'https://github.com/AdguardTeam/AdGuardHome/releases/download/v1.0.0/AdGuardHome_linux_amd64.tar.gz'
ARCHIVE_SHA256 = '19e023d98eb42eb1cdbfd6e4b6ebc937dade59e969506c62eafb3a3d6d2c1e4f'
ROOT = Path(__file__).resolve().parent


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def validate(binary=None):
    candidate = ROOT / 'adguard.txt'
    manifest = json.loads((ROOT / 'status.json').read_text())
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() == manifest['sha256']
    with tempfile.TemporaryDirectory(prefix='adguard-validation-') as directory:
        work = Path(directory)
        if binary:
            executable = Path(binary).resolve()
        else:
            with urlopen(ARCHIVE, timeout=90) as response:
                archive = response.read(50_000_001)
            assert hashlib.sha256(archive).hexdigest() == ARCHIVE_SHA256, 'official binary checksum mismatch'
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                member = next(m for m in tar.getmembers() if m.isfile() and PurePosixPath(m.name).name == 'AdGuardHome')
                executable = work / 'AdGuardHome'
                executable.write_bytes(tar.extractfile(member).read())
            executable.chmod(0o700)
        version = subprocess.check_output([str(executable), '--version'], text=True).strip()
        assert VERSION in version
        web_port, dns_port = free_port(), free_port()
        config = work / 'AdGuardHome.yaml'
        config.write_text(f'''http:
  address: 127.0.0.1:{web_port}
dns:
  bind_hosts: [127.0.0.1]
  port: {dns_port}
  upstream_dns: [1.1.1.1]
filters: []
whitelist_filters: []
user_rules: []
users: []
filtering:
  safe_fs_patterns:
    - {json.dumps(str(candidate))}
  protection_enabled: true
  filtering_enabled: true
schema_version: 35
''')
        def request(path, data=None):
            req = Request(f'http://127.0.0.1:{web_port}/control/' + path,
                          data=None if data is None else json.dumps(data).encode(),
                          headers={'Content-Type': 'application/json'})
            with urlopen(req, timeout=20) as response:
                raw = response.read()
            try:
                return json.loads(raw)
            except ValueError:
                return raw.decode()
        with open(work / 'engine.log', 'w') as log:
            process = subprocess.Popen([str(executable), '--no-check-update', '-c', str(config), '-w', str(work)],
                                       stdout=log, stderr=subprocess.STDOUT,
                                       env={**os.environ, 'GOMEMLIMIT': '128MiB'})
            try:
                for attempt in range(100):
                    try:
                        request('status')
                        break
                    except OSError:
                        if process.poll() is not None or attempt == 99:
                            raise RuntimeError((work / 'engine.log').read_text())
                        time.sleep(0.1)
                print(request('filtering/add_url', {'name': 'Candidate', 'url': str(candidate), 'whitelist': False}))
                for attempt in range(100):
                    if request('filtering/check_host?name=doubleclick.net&qtype=A')['reason'] == 'FilteredBlackList':
                        break
                    time.sleep(0.1)
                checks = {}
                expected = {'doubleclick.net': 'FilteredBlackList', 'ad.azure.com': 'NotFilteredWhiteList',
                            'adfractal.com': 'RewriteRule', 'analytics.example.org': 'FilteredBlackList'}
                for host, reason in expected.items():
                    result = request('filtering/check_host?name=' + host + '&qtype=A')
                    assert result['reason'] == reason, (host, result)
                    checks[host] = {'reason': result['reason'], 'rules': [r['text'] for r in result['rules']], 'cname': result['cname']}
                assert checks['adfractal.com']['cname'] == 'ad-block.dns.adguard.com'
                status = request('filtering/status')
                assert len(status['filters']) == 1
                assert status['filters'][0]['rules_count'] == manifest['rules']
                memory = {}
                for line in Path(f'/proc/{process.pid}/status').read_text().splitlines():
                    if line.startswith(('VmHWM:', 'VmRSS:')):
                        memory[line.split(':')[0] + '_KiB'] = int(line.split()[1])
                assert memory['VmHWM_KiB'] < 256 * 1024, 'engine peak RSS exceeds 256 MiB budget'
                report = {'validated_at': datetime.now(timezone.utc).isoformat(), 'engine': version,
                          'platform': 'Linux amd64', 'gomemlimit': '128MiB', 'memory': memory,
                          'rules_loaded': manifest['rules'], 'bytes': manifest['bytes'],
                          'subscription_sha256': manifest['sha256'], 'checks': checks,
                          'scope': 'Isolated engine load and rule matching test; not a GL-MT3600BE hardware benchmark.'}
                (ROOT / 'consumer-validation.json').write_text(json.dumps(report, indent=2) + '\n')
                print(json.dumps(report, indent=2))
                if os.environ.get('GITHUB_STEP_SUMMARY'):
                    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
                        stream.write(f'\n## AdGuard Home validation\n\n{version}: loaded {manifest["rules"]:,} rules. Block, allow, regex and DNS rewrite checks passed. Peak RSS: {memory["VmHWM_KiB"] / 1024:.1f} MiB (Linux amd64; not router hardware).\n')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', help='Existing official Linux amd64 AdGuardHome binary (for local testing)')
    args = parser.parse_args()
    validate(args.binary)
