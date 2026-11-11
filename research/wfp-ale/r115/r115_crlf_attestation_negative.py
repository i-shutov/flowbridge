#!/usr/bin/env python3
"""R115: exact-byte attestation negatives; offline, no Windows/WFP/driver/network."""
import hashlib
import pathlib
import subprocess

EXPECTED = '49506ca07145c18947a0845f2a1a63b3de1f54ec'
ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = subprocess.run(['git', 'cat-file', 'blob', EXPECTED],
                        cwd=ROOT, check=True, capture_output=True).stdout

def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()

def canonical(data):
    return data.replace(b'\r\n', b'\n')

def allow(data):
    return blob(data) == EXPECTED or blob(canonical(data)) == EXPECTED

parts = SOURCE.split(b'\n')
mixed = b''.join(p + (b'\r\n' if i % 2 == 0 else b'\n')
                 for i,p in enumerate(parts[:-1])) + parts[-1]
cases = [
    ('canonical_lf', SOURCE, True),
    ('all_crlf', SOURCE.replace(b'\n', b'\r\n'), True),
    ('mixed_lf_crlf', mixed, True),
    ('nul_appended', SOURCE+b'\0', False),
    ('truncated', SOURCE[:-1], False),
    ('double_cr', SOURCE.replace(b'\n', b'\r\r\n'), False),
    ('bom', b'\xef\xbb\xbf'+SOURCE, False),
    ('stray_cr', SOURCE+b'\r', False),
]
for i in range(0,len(SOURCE),151):
    changed = bytearray(SOURCE); changed[i] ^= 1
    cases.append(('mutant_%05d' % i, bytes(changed), False))

assert blob(SOURCE) == EXPECTED
assert blob(cases[1][1]) != EXPECTED
assert canonical(cases[1][1]) == SOURCE
assert len(cases) == 135
rows=[]
for label,data,expected in cases:
    result=allow(data)
    assert result == expected, (label,result)
    rows.append('%s,%s,%s,%d' % (label,blob(data),blob(canonical(data)),int(result)))
    cli=subprocess.run(['git','hash-object','--stdin'],input=data,
                       check=True,capture_output=True).stdout.decode().strip()
    assert cli == blob(data), label
matrix='\n'.join(rows)+'\n'
digest=hashlib.sha256(matrix.encode('ascii')).hexdigest()
assert digest == '0abcfc37018f43751e1e2d19419c4be048d075a0ae4abef56b338db7d2bfc8e3'
script=(ROOT/'research/wfp-ale/r112/R112_WINDOWS_NATIVE_READONLY_CHECK.ps1').read_text(encoding='utf8')
for item in ['r115-canonical-source.rs','Git-BlobSha1 $canonicalPath',
             '$resolved = $canonicalPath','if ($normalizedBlob -ne $expectedGitBlob)']:
    assert item in script, item
print('PASS R115: 135 cases, 3 canonical/mixed accepted, 132 corrupt rejected')
print('R115_MATRIX_SHA256='+digest)
print('NO_WINDOWS_OR_KERNEL_PROOF')
