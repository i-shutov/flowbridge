from pathlib import Path
import base64, hashlib, subprocess, zlib
parts=[Path(f'tools/native-patch.{n}').read_text().strip() for n in range(3)]
# Correct transport transcription before verifying the immutable patch digest.
for a,b in [('BGmqKvKvVAh','BGmqKvVAh'),('O7u9IS+co43E2','O7u9IS+43E2'),('sfv6f/PphbfPg3','sfv6fP/8bfPg3'),('7g0DP+UUNq4inGE2','7g0DP+Uq4inGE2')]:
    assert parts[1].count(a)==1
    parts[1]=parts[1].replace(a,b)
assert len(parts[1])==7600
raw=zlib.decompress(base64.b64decode(''.join(parts),validate=True))
assert hashlib.sha256(raw).hexdigest()=='51aaaab99fac16ff61105eae196f4954dca7c4058cd9e58f92d6b542481d769d'
p=Path('/tmp/flowbridge-native.patch');p.write_bytes(raw)
subprocess.run(['git','apply','--check',str(p)],check=True)
subprocess.run(['git','apply',str(p)],check=True)
print('Verified native vertical patch applied')
