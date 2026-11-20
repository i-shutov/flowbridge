// R217: independent subprocess oracle for the R216 test process contract.
// Read-only; no networking, Windows APIs, drivers, filters, or third-party code.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const pyFile = join(root, 'r216_dualstack_negative.py');
const py = process.env.PYTHON || 'python3';
const expected = 'R216 rows=12 sha256=bcb20d46677ab067651521c4c066c8bed5701d9321ae578a30d813c332c213dc';
const invoke = file => {
  const r = spawnSync(py, [file], { encoding: 'utf8', timeout: 10000 });
  assert.ifError(r.error);
  assert.equal(r.signal, null);
  return { code: r.status, output: (r.stdout || '') + (r.stderr || '') };
};
const original = readFileSync(pyFile, 'utf8');
assert.match(original, /if not result\.wasSuccessful\(\):\s*raise SystemExit\(1\)/);
const clean = invoke(pyFile);
assert.equal(clean.code, 0, clean.output);
assert.match(clean.output, /Ran 4 tests/);
assert.ok(clean.output.includes(expected), clean.output);

const exactGuard = "and not (ip[:10] == bytes(10) and ip[10:12] == b'\\xff\\xff'))";
assert.equal(original.split(exactGuard).length, 2, 'guard must occur exactly once');
const mutated = original.replace(exactGuard, 'and True)');
const dir = mkdtempSync(join(tmpdir(), 'fb-r217-negative-'));
try {
  const badFile = join(dir, 'mutant.py');
  writeFileSync(badFile, mutated, { encoding: 'utf8', mode: 0o600 });
  const bad = invoke(badFile);
  assert.notEqual(bad.code, 0, 'mutated destination policy must fail the process');
  assert.match(bad.output, /FAILED \(failures=/);
  assert.ok(!bad.output.includes(expected), 'failed tests must not emit positive transcript');
  console.log('R217 PASS: baseline exit=0 and sha256 intact; mapped-guard mutant exit!=0 without positive transcript');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
