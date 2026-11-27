#!/usr/bin/env python3
"""Conservative AdGuard Home merger. Python standard library only."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from datetime import datetime, timezone
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 4_100_000  # Two copies < 8.5 MB; leave room for update staging.
MAX_RULES = 200_000
MAX_DOWNLOAD = 12_000_000
SOURCES = [
    ('anti-ad', 'anti-AD', 'https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt', 30000, 'https://github.com/privacy-protection-tools/anti-AD'),
    ('awavenue', 'AWAvenue / 秋风广告规则', 'https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt', 100, 'https://github.com/TG-Twilight/AWAvenue-Ads-Rule'),
    ('popup', 'AdGuard DNS Popup Hosts filter', 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/adguard_popup_filter.txt', 100, 'https://github.com/AdguardTeam/AdGuardSDNSFilter'),
    ('hagezi', 'HaGeZi Multi PRO mini', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt', 30000, 'https://github.com/hagezi/dns-blocklists'),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(data, minimum=1):
    if not data or len(data) > MAX_DOWNLOAD:
        raise ValueError('empty or oversized source')
    text = data.decode('utf-8-sig')
    if '\x00' in text or re.search(r'<(?:!doctype|html|body|script)\b', text, re.I):
        raise ValueError('HTML or binary response')
    rules = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(('!', '#')) or line in ('[Adblock Plus]', '[Adblock Plus 2.0]'):
            continue
        # Preserve every supported upstream rule verbatim, including @@, regex,
        # $important, $badfilter, $dnsrewrite and other DNS modifiers.
        # Fail closed on an unexpected source format instead of dropping lines.
        base = line[2:] if line.startswith('@@') else line
        if not (base.startswith(('||', '|', '/')) or re.fullmatch(r'[\w.*-]+\.[\w.*-]+(?:\^)?(?:\$[^\r\n]+)?', base)):
            raise ValueError('unrecognized rule: ' + line[:120])
        if any(x in line for x in ('##', '#@#', '#$#', '#?#', '#%#')):
            raise ValueError('browser-only cosmetic rule')
        rules.add(line)
    if len(rules) < minimum:
        raise ValueError(f'too few rules: {len(rules)} < {minimum}')
    return rules


def download(url):
    error = None
    for attempt in range(3):
        try:
            request = Request(url, headers={'User-Agent': 'adguard-privacy/1.0', 'Accept-Encoding': 'identity'})
            with urlopen(request, timeout=45) as response:
                if response.status != 200:
                    raise ValueError(f'HTTP {response.status}')
                data = response.read(MAX_DOWNLOAD + 1)
                if len(data) > MAX_DOWNLOAD:
                    raise ValueError('download exceeds limit')
                if response.headers.get('Content-Length') and len(data) != int(response.headers['Content-Length']):
                    raise ValueError('incomplete download')
                return data
        except Exception as exc:
            error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
    raise RuntimeError(str(error))


def select_source(source, previous, cache, fetch=download):
    key, name, url, minimum, homepage = source
    old_data = None
    if previous:
        old_data = gzip.decompress(cache.read_bytes())
        if digest(old_data) != previous['sha256']:
            raise ValueError(f'{key}: cache integrity mismatch')
        parse(old_data, minimum)
    try:
        data = fetch(url)
        rules = parse(data, minimum)
        if previous and len(rules) < previous['rules'] * 0.70:
            raise ValueError('rule count dropped by over 30%; retaining previous snapshot')
        state = 'fresh'
        error = None
        fetched_at = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        if old_data is None:
            raise RuntimeError(f'{key}: first download failed; no valid snapshot: {exc}') from exc
        data, rules = old_data, parse(old_data, minimum)
        state, error = 'cached', str(exc)
        fetched_at = previous['fetched_at']
        print(f'WARNING: {key}: {error}; using last good snapshot')
    return data, rules, dict(name=name, url=url, homepage=homepage, rules=len(rules), bytes=len(data), sha256=digest(data), status=state, error=error, fetched_at=fetched_at)


def compact(rules):
    # Remove only plain blocking rules already covered by an active parent.
    # Exceptions and modified/regex rules remain byte-for-byte unchanged.
    plain = {r[2:-1]: r for r in rules if re.fullmatch(r'\|\|[a-z0-9_.-]+\^', r)}
    disabled = {r[:-10] for r in rules if r.endswith('$badfilter')}
    parents = {domain for domain, rule in plain.items() if rule not in disabled}
    redundant = set()
    for domain, rule in plain.items():
        if rule in disabled:
            continue
        parts = domain.split('.')
        if any('.'.join(parts[i:]) in parents for i in range(1, len(parts))):
            redundant.add(rule)
    return rules - redundant


def render(groups, now, max_bytes=MAX_BYTES, max_rules=MAX_RULES):
    rules = compact(set().union(*groups))
    if not rules or len(rules) > max_rules:
        raise ValueError(f'rule-count budget exceeded: {len(rules)}')
    # Never normalize modifiers, remove exceptions, or truncate to fit.
    header = ['! Title: AdGuard Privacy - GL-MT3600BE', '! Expires: 1 day',
              '! Homepage: https://github.com/dijunux/adguard-privacy',
              '! Updated: ' + now, '! Rules: ' + str(len(rules)),
              '! Upstream rules retain their original licenses; see sources/ and README.md.']
    header += ['! Source: ' + source[1] + ' - ' + source[4] for source in SOURCES]
    data = ('\n'.join(header + sorted(rules)) + '\n').encode('utf-8')
    if len(data) > max_bytes:
        raise ValueError(f'size budget exceeded: {len(data)} > {max_bytes}; previous publication retained')
    return data, rules


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_bytes(data)
    os.replace(temporary, path)


def build(root=ROOT, fetch=download):
    manifest = root / 'status.json'
    old = json.loads(manifest.read_text()) if manifest.exists() else {}
    now = datetime.now(timezone.utc).isoformat()
    selected, groups, statuses = {}, [], {}
    for source in SOURCES:
        key = source[0]
        data, rules, status = select_source(source, old.get('sources', {}).get(key), root / 'sources' / (key + '.txt.gz'), fetch)
        selected[key], statuses[key] = data, status
        groups.append(rules)
    data, rules = render(groups, now)
    # No output or cache is changed until ALL sources and budgets pass.
    # Git publication is a single commit; any later failure prevents publishing.
    for key, raw in selected.items():
        atomic_write(root / 'sources' / (key + '.txt.gz'), gzip.compress(raw, mtime=0))
    status = dict(updated_at=now, bytes=len(data), max_bytes=MAX_BYTES, rules=len(rules),
                  input_rules=sum(map(len, groups)), exact_duplicates_removed=sum(map(len, groups))-len(set().union(*groups)),
                  covered_subdomains_removed=len(set().union(*groups))-len(rules),
                  allow_rules=sum(r.startswith('@@') for r in rules),
                  special_rules=sum(not re.fullmatch(r'(?:@@)?\|\|[a-z0-9_.-]+\^', r) for r in rules),
                  sha256=digest(data), sources=statuses)
    atomic_write(root / 'adguard.txt', data)
    atomic_write(manifest, (json.dumps(status, ensure_ascii=False, indent=2) + '\n').encode())
    print(json.dumps(status, ensure_ascii=False, indent=2))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write(f'## Filter build\n\n{len(rules):,} rules; {len(data):,} bytes / {MAX_BYTES:,}; {status["allow_rules"]} allow rules; {status["special_rules"]} special rules.\n\n')
            stream.write('| Source | State | Rules |\n|---|---|---:|\n')
            for row in statuses.values():
                stream.write(f'| {row["name"]} | {row["status"]} | {row["rules"]} |\n')
    return status


class SafetyTests(unittest.TestCase):
    def test_preserve_semantics(self):
        lines = {'*-ad.sm.cn*', '@@||allow.example^', '||ads.example^', '||ads.example^$badfilter',
                 '/ad[0-9]+\\.example/', '||rewrite.example^$dnsrewrite=NOERROR;A;0.0.0.0',
                 '||important.example^$important'}
        raw = ('\n'.join(lines)+'\n').encode()
        data, merged = render([parse(raw), parse(raw)], 'test')
        self.assertEqual(merged, lines)
        self.assertEqual(parse(data), lines)

    def test_parent_compaction_respects_exceptions_and_badfilter(self):
        rules = {'||ads.example^', '||child.ads.example^', '@@||allow.ads.example^',
                 '||child.ads.example^$important', '||off.example^', '||off.example^$badfilter',
                 '||child.off.example^', '||child.off.example^$dnsrewrite=0.0.0.0'}
        result = compact(rules)
        self.assertEqual(result, rules - {'||child.ads.example^'})

    def test_invalid_source(self):
        for data in (b'', b'<html>unavailable</html>', b'{"error": "rate limit"}', b'\x00'):
            with self.assertRaises((ValueError, UnicodeError)):
                parse(data)

    def test_budget_rejects_without_truncating(self):
        with self.assertRaises(ValueError):
            render([{'@@||keep.example^', '||ads.example^'}], 'test', max_bytes=20)
        with self.assertRaises(ValueError):
            render([{'||a.example^', '||b.example^'}], 'test', max_rules=1)

    def test_fallback_and_truncation(self):
        source = ('test', 'test', 'https://example.invalid', 1, '')
        old = b'||one.example^\n@@||two.example^\n||three.example^$important\n'
        meta = dict(sha256=digest(old), rules=3, fetched_at='old')
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / 'cache.gz'
            cache.write_bytes(gzip.compress(old))
            def offline(url):
                raise OSError('simulated outage')
            for fetch in (offline, lambda u: b'<html>error</html>', lambda u: b'||one.example^\n'):
                data, rules, state = select_source(source, meta, cache, fetch)
                self.assertEqual(data, old)
                self.assertEqual(state['status'], 'cached')
                self.assertEqual(state['fetched_at'], 'old')
            with self.assertRaises(RuntimeError):
                select_source(source, None, cache, offline)
            cache.write_bytes(gzip.compress(b'||tampered.example^\n'))
            with self.assertRaises(ValueError):
                select_source(source, meta, cache, offline)

    def test_failed_build_keeps_previous_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'adguard.txt').write_bytes(b'previous valid publication')
            with self.assertRaises(RuntimeError):
                build(root, lambda u: b'<html>broken</html>')
            self.assertEqual((root / 'adguard.txt').read_bytes(), b'previous valid publication')
            self.assertFalse((root / 'status.json').exists())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()
    if args.test:
        unittest.main(argv=['update_rules.py'], verbosity=2)
    else:
        build()
