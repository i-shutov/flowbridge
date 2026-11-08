"""R33: offline, deterministic counterexample for SOCKS peer identity.

This models the *broker-observable* transcript, NOT an exploit, WFP runtime,
SOCKS listener binding race, or an authenticated kernel-origin witness.
No drivers, sockets, processes, SSH, BFE or network APIs are used.
"""
from dataclasses import dataclass
from pathlib import Path
import hashlib
import unittest

BRANCH = 'research/windows-wfp-ale-attribution-20261107'
SOURCE_SHA = {
    'research/wfp-ale/kernel-r19/broker.rs': '825cb0a053dca0259a81fe77cdad9227c71883ae',
    'research/wfp-ale/kernel-r19/broker_windows.rs': 'f315d2cfab16ed7474446a9bb819980c8c737163',
    'research/wfp-ale/kernel-r19/transport.rs': '414458795896f02ac7f6c92ec5f455b9268551e4',
}

@dataclass(frozen=True)
class World:
    family: int
    ssh_alive: bool
    actual_listener: str          # hidden from the broker: 'ssh' or 'other'
    callback_and_claim: bool      # GIVEN hypothetical valid WFP proof
    listener_available: bool
    correct_socks_reply: bool


def observed(world: World) -> tuple:
    """Only facts available to this experimental broker's outbound leg."""
    destination = bytes([192, 0, 2, 45]) if world.family == 4 else bytes.fromhex('20010db8000000000000000000000045')
    request = bytes([5, 1, 0, 1 if world.family == 4 else 4]) + destination + bytes([1, 187])
    # WFP receipt pertains to the *incoming* selected app, not SOCKS listener.
    return (world.callback_and_claim, '127.0.0.1', 1080,
            bytes([5, 1, 0]), bytes([5, 0]) if world.correct_socks_reply else bytes([5, 255]),
            request, bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]) if world.correct_socks_reply else b'')


def source_like_admission(world: World) -> bool:
    """Boundary-only abstraction: claim then TCP then valid SOCKS response."""
    return world.callback_and_claim and world.listener_available and world.correct_socks_reply


def required_admission(world: World) -> bool:
    """More demanding objective: data must go only to authenticated SSH."""
    return source_like_admission(world) and world.actual_listener == 'ssh' and world.ssh_alive


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def check_optional_exact_checkout(root: Path) -> None:
    """If full checkout is present, reject changed source, don't silently skip."""
    for relative, sha in SOURCE_SHA.items():
        content = (root / relative).read_bytes()
        assert git_blob(content) == sha, (relative, 'source_sha_mismatch')
    broker = (root / 'research/wfp-ale/kernel-r19/broker_windows.rs').read_text()
    transport = (root / 'research/wfp-ale/kernel-r19/transport.rs').read_text()
    launcher = (root / 'research/wfp-ale/kernel-r19/broker.rs').read_text()
    assert 'device.command(h::CLAIM,&self.context.0)?;' in broker
    assert 'WSAIoctl(s.0,SET_RECORDS' in broker
    assert 'ip:[127,0,0,1]' in broker
    assert 'socket(2,1,6)' in broker
    assert 'crate::transport::socks_connect(&mut self.upstream,self.destination)?;' in broker
    assert 's.write_all(&[5,1,0])?' in transport
    assert 'if response!=[5,0]' in transport
    assert 'if h[..3]!=[5,0,0]' in transport
    assert 'destination.write_all(&data[..n])?' in transport
    assert 'ssh_port:u16' in launcher
    assert 'claim_and_connect(&d,ssh_port)?' in launcher

class OfflineIdentityCounterexample(unittest.TestCase):
    def test_socks_greeting_selects_no_authentication(self):
        for family in (4, 6):
            w = World(family, True, 'ssh', True, True, True)
            self.assertEqual(observed(w)[3], b'\x05\x01\x00')
            self.assertEqual(observed(w)[4], b'\x05\x00')

    def test_valid_but_different_peer_is_indistinguishable(self):
        for family in (4, 6):
            correct = World(family, True, 'ssh', True, True, True)
            substitution = World(family, False, 'other', True, True, True)
            self.assertEqual(observed(correct), observed(substitution))
            self.assertTrue(source_like_admission(correct))
            self.assertTrue(source_like_admission(substitution))
            self.assertFalse(required_admission(substitution))

    def test_same_original_5tuple_ticket_does_not_authenticate_upstream(self):
        for family in (4, 6):
            same_ticket = World(family, False, 'other', True, True, True)
            self.assertTrue(source_like_admission(same_ticket))
            self.assertFalse(required_admission(same_ticket))

    def test_no_listener_fails_closed_at_connect(self):
        for family in (4, 6):
            w = World(family, False, 'other', True, False, True)
            self.assertFalse(source_like_admission(w))

    def test_bad_socks_reply_rejected_not_peer_proof(self):
        for family in (4, 6):
            w = World(family, False, 'other', True, True, False)
            self.assertFalse(source_like_admission(w))
            self.assertFalse(required_admission(w))

    def test_missing_kernel_claim_fails_independently(self):
        for family in (4, 6):
            w = World(family, True, 'ssh', False, True, True)
            self.assertFalse(source_like_admission(w))

    def test_ipv4_ipv6_destinations_share_same_local_ipv4_peer_boundary(self):
        a = observed(World(4, True, 'ssh', True, True, True))
        b = observed(World(6, True, 'ssh', True, True, True))
        self.assertEqual(a[1:5], b[1:5]);self.assertNotEqual(a[5], b[5])
        self.assertEqual(a[5][3], 1);self.assertEqual(b[5][3], 4)

    def test_permit_does_not_imply_physical_ssh_channel(self):
        worlds = [World(f, False, 'other', True, True, True) for f in (4, 6)]
        self.assertTrue(all(source_like_admission(w) and not required_admission(w) for w in worlds))

if __name__ == '__main__':
    unittest.main()
