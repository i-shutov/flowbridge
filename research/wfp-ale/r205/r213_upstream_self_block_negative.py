#!/usr/bin/env python3
"""R213 conditional source-level negative: propagated ORIGINAL_APP_ID may self-block SSH.
Offline model only. Never opens BFE, sockets, installs filters or drivers.
"""
from dataclasses import dataclass
from hashlib import sha1
from pathlib import Path
import sys

PINS = {
    'kernel-r19/policy_plan.rs': '0c3d0e88eb9d06f4030131d9533da2d629dbdab0',
    'kernel-r19/policy_windows.rs': 'acf60334320d970f58af3349ee75fbaa59826602',
    'kernel-r19/broker_windows.rs': '329ef14b63e70226bfad7372b0014559213abd04',
    'kernel-r19/kernel/src/redirect.rs': 'a093f049d162987981a957aac90db1014bc6ff09',
}

def source_guards(root: Path):
    src = {}
    for name, expected in PINS.items():
        data = (root / name).read_bytes()
        got = sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        assert got == expected, (name, got, expected)
        src[name] = data.decode('utf-8')
    plan, policy, broker, redirect = (src[name] for name in PINS)
    ssh = broker.split('pub fn claim_and_connect_trusted_ssh(', 1)[1].split('impl TrustedSshRelay {', 1)[0]
    auth = redirect.split('pub unsafe fn auth_classify(', 1)[1]
    checks = {
        'two family AUTH rules': 'kind:Kind::AttestOriginal' in plan and 'Family::V6,kind:Kind::AttestOriginal' in plan,
        'AUTH original AppId filter': 'FWPM_CONDITION_ALE_ORIGINAL_APP_ID' in policy,
        'AUTH TCP condition': 'FWPM_CONDITION_IP_PROTOCOL' in policy and 'Anonymous.uint8=6' in policy,
        'AUTH terminating action': 'FWP_ACTION_CALLOUT_TERMINATING' in policy,
        'records forwarded before SSH connect': ssh.find('WSAIoctl(s.0,SET_RECORDS') >= 0 and 0 <= ssh.find('WSAIoctl(s.0,SET_RECORDS') < ssh.find('connect(s.0,'),
        'physical SSH uses IPv4 TCP': 'socket(2,1,6)' in ssh and 'SocketAddrV4' in ssh,
        'original AppId tested by AUTH': 'original_matches_selected(orig,current_app,' in auth,
        'AUTH insists redirected connection flag': 'bits & 0x0010_0000==0' in auth,
        'AUTH insists loopback': 'if !loopback{return false;}' in auth,
        'AUTH insists local proxy port': 'actual_port != route.ports[' in auth,
        'AUTH denies failed predicate': 'if !auth_check(values,meta){block(out);return;}' in auth,
    }
    assert all(checks.values()), checks
    print(f'R213 source: {len(PINS)}/4 Git blob SHA, {sum(checks.values())}/{len(checks)} guards PASS')

@dataclass(frozen=True)
class Flow:
    family: int              # Actual socket IP family. R37 physical SSH is v4.
    protocol: int
    original_selected: bool  # WFP ORIGINAL_APP_ID propagation to this leg (assumption).
    redirected: bool
    loopback: bool
    broker_port: bool
    matched_origin: bool     # PID+epoch+endpoint+destination+auth ticket


def policy_hits(f: Flow) -> bool:
    return f.family in (4, 6) and f.protocol == 6 and f.original_selected


def kernel_auth_permits(f: Flow) -> bool:
    return f.redirected and f.loopback and f.broker_port and f.matched_origin


def final_state(f: Flow) -> str:
    if not policy_hits(f):
        return 'OUTSIDE_R19_AUTH_FILTER'
    return 'AUTH_PERMIT_CANDIDATE' if kernel_auth_permits(f) else 'AUTH_BLOCK_CANDIDATE'


def run():
    total = 0
    for original_target in (4, 6):
        # The R37 physical SSH socket remains IPv4 even for an IPv6 original target.
        genuine = Flow(original_target, 6, True, True, True, True, True)
        propagated_ssh = Flow(4, 6, True, False, False, False, False)
        unpropagated_ssh = Flow(4, 6, False, False, False, False, False)
        siblings = Flow(original_target, 6, False, False, False, False, False)
        udp = Flow(original_target, 17, True, False, False, False, False)
        cases = [(genuine,'AUTH_PERMIT_CANDIDATE'),
                 (propagated_ssh,'AUTH_BLOCK_CANDIDATE'),
                 (unpropagated_ssh,'OUTSIDE_R19_AUTH_FILTER'),
                 (siblings,'OUTSIDE_R19_AUTH_FILTER'),
                 (udp,'OUTSIDE_R19_AUTH_FILTER')]
        for flow, expected in cases:
            assert final_state(flow) == expected, (original_target,flow,expected)
            total += 1
        # Required counterfactual: a current BROKER AppId cannot suppress a
        # filter keyed to ORIGINAL AppId; in model, current AppId is deliberately absent.
        assert policy_hits(propagated_ssh)
        assert not kernel_auth_permits(propagated_ssh)
        total += 2
    assert total == 14
    print('R213 Python: 14/14 conditional scenarios PASS; physical SSH IPv4, source target IPv4/IPv6; no native WFP proof')

if __name__ == '__main__':
    if '--source' in sys.argv:
        source_guards(Path(__file__).resolve().parents[1])
    run()
