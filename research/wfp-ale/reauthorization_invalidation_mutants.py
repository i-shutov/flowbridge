#!/usr/bin/env python3
"""R13 independent mutation sensitivity: each unsafe fail-open mutant must fail audit.

No network, WFP, drivers, sockets or OS modifications. Code is executed in an
isolated Python module dictionary, never written to the repository.
"""
from __future__ import annotations
import contextlib
import io
from pathlib import Path
import sys
import types
import reauthorization_invalidation_audit as audit

source = Path(__file__).with_name('endpoint_witness_model.py').read_text('utf-8')
mutations = {
    'ignore_reauthorization': (
        "if event.reauthorize is True:\n            if pending:\n                self._retire_endpoint(event.endpoint)",
        "if event.reauthorize is True:\n            if pending:\n                pass"),
    'ignore_invalid_auth': (
        "if (event.reauthorize is not False or event.family not in (4, 6)\n                or not event.path_identity):\n            if pending:\n                self._retire_endpoint(event.endpoint)",
        "if (event.reauthorize is not False or event.family not in (4, 6)\n                or not event.path_identity):\n            if pending:\n                pass"),
    'treat_missing_reauth_flag_as_false': (
        'if (event.reauthorize is not False or event.family not in (4, 6)',
        'if (event.reauthorize is True or event.family not in (4, 6)'),
    'poison_wrong_endpoint': (
        'self._retire_endpoint(event.endpoint)',
        'self._retire_endpoint(event.endpoint + 1)'),
    'skip_reauth_when_path_empty': (
        'if event.reauthorize is True:',
        "if event.reauthorize is True and bool(event.path_identity):"),
}
assert audit.run()['r13_cases_passed'] == 38
originals = (audit.Authorization, audit.Owner, audit.Redirect, audit.ResearchGate)
count = 0
for name, (from_s, to_s) in mutations.items():
    assert from_s in source, name
    changed = source.replace(from_s, to_s, 1 if name != 'poison_wrong_endpoint' else -1)
    assert changed != source
    mname = 'r13_mutant_'+name
    m = types.ModuleType(mname)
    m.__file__ = '<in-memory-r13-mutant>'
    sys.modules[mname] = m
    exec(compile(changed, mname, 'exec'), m.__dict__)
    audit.Authorization, audit.Owner, audit.Redirect, audit.ResearchGate = (
        m.Authorization, m.Owner, m.Redirect, m.ResearchGate)
    try:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                audit.run()
        except AssertionError:
            count += 1
        else:
            raise AssertionError('UNSAFE MUTANT MISSED: ' + name)
    finally:
        audit.Authorization, audit.Owner, audit.Redirect, audit.ResearchGate = originals
        del sys.modules[mname]
assert count == len(mutations), (count, len(mutations))
print({'mutants_rejected':count, 'synthetic_only':True,
       'kernel_origin_proved':False,'packetbound':False,'system_no_direct':False})
