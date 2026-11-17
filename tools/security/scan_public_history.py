#!/usr/bin/env python3
"""Read-only high-confidence Git/ZIP secret screening. NEVER outputs matched bytes.

Coverage is deliberately bounded and reported. This is not a full security
audit or proof that public history was never copied before a privacy change.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from zipfile import ZipFile, BadZipFile

PATTERNS = {
    'private_key_pem': re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----'),
    'github_token_classic': re.compile(rb'gh[pousr]_[A-Za-z0-9_]{30,}'),
    'github_token_fine_grained': re.compile(rb'github_pat_[A-Za-z0-9_]{50,}'),
    'aws_access_key_id': re.compile(rb'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])'),
    'slack_token': re.compile(rb'xox[baprs]-[0-9A-Za-z-]{24,}'),
    'stripe_live_key': re.compile(rb'sk_live_[A-Za-z0-9]{24,}'),
}
MAX_ITEM = 3_000_000
MAX_ITEMS = 150_000
MAX_ZIP_ITEMS = 2000
# Exactly one synthetic token-shaped fixture was temporarily committed in
# three historical blob versions of the SSH privacy regression test (#84).
# Split the bytes here to avoid introducing another scanner finding.
# Do not suppress generic test files, paths, or actual high-confidence rules.
EXACT_SYNTHETIC_FIXTURE = b"gh" + b"p_SYNTHETICSECRETDO_NOT_LOG_THIS_VALUE123456789"

def match_kinds(data: bytes) -> list[str]:
    # Suppress ONLY the exact known synthetic fixture from our SSH privacy
    # regression. Other token-shaped values in the same blob still alert.
    normalized = data.replace(EXACT_SYNTHETIC_FIXTURE, b"[SYNTHETIC_TEST_FIXTURE]")
    # No matching value, snippet, local path, hostname or username escapes.
    return [kind for kind, regex in PATTERNS.items() if regex.search(normalized)]

def run_git(root: Path, args: list[str]) -> bytes:
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL)

def scan_git(root: Path) -> dict:
    # --all includes all locally fetched refs, not inaccessible external forks.
    rows = run_git(root, ['rev-list', '--objects', '--all']).splitlines()
    ids = list(dict.fromkeys(row.split(b' ', 1)[0] for row in rows))
    if len(ids) > MAX_ITEMS:
        raise RuntimeError('too_many_git_objects')
    proc = subprocess.Popen(['git', '-C', str(root), 'cat-file', '--batch'],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    hits = []
    reviewed = 0
    oversize = 0
    known_synthetic_fixtures = 0
    try:
        assert proc.stdin is not None and proc.stdout is not None
        for oid in ids:
            proc.stdin.write(oid + b'\n')
            proc.stdin.flush()
            header = proc.stdout.readline().split()
            if len(header) != 3 or header[0] != oid:
                raise RuntimeError('git_object_header_invalid')
            typ, size = header[1], int(header[2])
            if size < 0 or size > 500_000_000:
                raise RuntimeError('git_object_invalid_size')
            if size > MAX_ITEM:
                remain = size
                while remain:
                    chunk = proc.stdout.read(min(65536, remain))
                    if not chunk:
                        raise RuntimeError('git_object_unexpected_eof')
                    remain -= len(chunk)
                oversize += int(typ == b'blob')
            else:
                data = proc.stdout.read(size)
                if len(data) != size:
                    raise RuntimeError('git_object_unexpected_eof')
                if typ == b'blob':
                    reviewed += 1
                    known_synthetic_fixtures += data.count(EXACT_SYNTHETIC_FIXTURE)
                    hits.extend({'rule': kind, 'object_id_prefix': oid.decode('ascii')[:12]}
                                for kind in match_kinds(data))
            if proc.stdout.read(1) != b'\n':
                raise RuntimeError('git_object_separator_invalid')
        proc.stdin.close()
        if proc.wait(timeout=15) != 0:
            raise RuntimeError('git_cat_file_failed')
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc.stdout is not None:
            proc.stdout.close()
    return {'source': 'all_fetched_git_refs', 'total_git_objects': len(ids),
            'scanned_blobs': reviewed, 'skipped_large_blobs': oversize,
            'known_exact_synthetic_test_fixtures_suppressed': known_synthetic_fixtures,
            'redacted_findings': hits,
            'finding_rule_counts': dict(Counter(x['rule'] for x in hits))}

def scan_zip(path: Path) -> dict:
    hits = []
    checked = skipped = 0
    with ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_ZIP_ITEMS:
            raise RuntimeError('zip_too_many_entries')
        for info in infos:
            if info.is_dir():
                continue
            raw = info.orig_filename
            if ('\\' in raw or raw.startswith(('/', './')) or '..' in raw.split('/')
                or info.filename != raw or
                (info.external_attr >> 16) & 0o170000 == 0o120000):
                raise RuntimeError('unsafe_zip_member')
            if info.file_size > MAX_ITEM:
                skipped += 1
                continue
            data = z.read(info)
            checked += 1
            ident = hashlib.sha256(data).hexdigest()[:12]
            hits.extend({'rule': kind, 'content_sha256_prefix': ident}
                        for kind in match_kinds(data))
    return {'source': 'owner_supplied_zip', 'scanned_files': checked,
            'skipped_large_files': skipped, 'redacted_findings': hits,
            'finding_rule_counts': dict(Counter(x['rule'] for x in hits))}

def main() -> int:
    cli = argparse.ArgumentParser()
    src = cli.add_mutually_exclusive_group(required=True)
    src.add_argument('--git-repo', type=Path)
    src.add_argument('--zip-file', type=Path)
    cli.add_argument('--out', type=Path, required=True)
    args = cli.parse_args()
    report = {'schema': 'flowbridge-secret-scan-v1', 'status': 'BLOCKED',
              'secret_values_exported': False, 'complete_secret_audit': False,
              'error_code': None}
    rc = 2
    try:
        payload = scan_git(args.git_repo) if args.git_repo else scan_zip(args.zip_file)
        report.update(payload)
        report['status'] = ('REVIEW_REQUIRED_HIGH_CONFIDENCE_FINDINGS' if payload['redacted_findings']
                            else 'PARTIAL_REVIEW_REQUIRED_OVERSIZED_ITEMS'
                            if payload.get('skipped_large_blobs', 0) or payload.get('skipped_large_files', 0)
                            else 'NO_HIGH_CONFIDENCE_SIGNATURES_IN_SCANNED_SCOPE')
        report['source_visibility_verified_private'] = False
        rc = 1 if (payload['redacted_findings'] or payload.get('skipped_large_blobs', 0)
                   or payload.get('skipped_large_files', 0)) else 0
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError, BadZipFile):
        report['error_code'] = 'SCANNER_FAILED_OR_UNTRUSTED_INPUT'
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf8')
    print(report['status'], 'findings', len(report.get('redacted_findings', [])),
          'objects_checked', report.get('scanned_blobs', report.get('scanned_files', 0)))
    return rc

if __name__ == '__main__':
    sys.exit(main())
