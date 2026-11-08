"""Executable negative tests for a pure model, independent of Win32/driver/SSH.

The model does not pretend to mint Windows handles or verify OpenSSH channels.
"""
from dataclasses import dataclass
import hashlib
import pathlib
import re
import unittest

@dataclass(frozen=True)
class Flow:
    ticket: int
    family: int
    proto: int = 6

@dataclass(frozen=True)
class Evidence:
    kind: str
    ticket: int = 0
    child: int = 0
    generation: int = 0

@dataclass
class Gate:
    flow: Flow
    child: int = 23
    generation: int = 9
    wfp_claim: bool = True
    wfp_alive: bool = True
    child_alive: bool = True
    remote_channel_proved: bool = False

    def decide(self, evidence: Evidence):
        if self.flow.proto != 6 or self.flow.ticket == 0 or not all(
            (self.wfp_claim, self.wfp_alive, self.child_alive)
        ):
            return "REJECT"
        if not (evidence.kind == "OWNED_PIPE" and
                evidence.ticket == self.flow.ticket and
                evidence.child == self.child and evidence.generation == self.generation and
                evidence.child > 0 and evidence.generation > 0):
            return "REJECT"
        return "CONDITIONAL_RELEASE" if self.remote_channel_proved else "LOCAL_PEER_ONLY"

class R34(unittest.TestCase):
    def test_local_loopback_no_auth_not_peer_identity(self):
        for family in (4,6):
            for kind in ("SOCKS5_NOAUTH", "PORT_PID_SNAPSHOT", "PROCESS_NAME_ONLY", "PING_READY"):
                with self.subTest(family=family,kind=kind):
                    self.assertEqual(Gate(Flow(31,family),remote_channel_proved=True).decide(Evidence(kind)),"REJECT")

    def test_owned_pipe_only_local_without_remote_witness(self):
        for family in (4,6):
            g=Gate(Flow(31,family))
            self.assertEqual(g.decide(Evidence("OWNED_PIPE",31,23,9)),"LOCAL_PEER_ONLY")
            g.remote_channel_proved=True
            self.assertEqual(g.decide(Evidence("OWNED_PIPE",31,23,9)),"CONDITIONAL_RELEASE")

    def test_ssh_restart_same_pid_generation_change(self):
        proof=Evidence("OWNED_PIPE",31,23,9)
        g=Gate(Flow(31,4),remote_channel_proved=True)
        self.assertEqual(g.decide(proof),"CONDITIONAL_RELEASE")
        g.child_alive=False
        self.assertEqual(g.decide(proof),"REJECT")
        restarted=Gate(Flow(31,4),generation=10,remote_channel_proved=True)
        self.assertEqual(restarted.decide(proof),"REJECT")

    def test_one_flow_cannot_borrow_a_sibling_receipt(self):
        p=Evidence("OWNED_PIPE",31,23,9)
        for t in (30,32,100):
            self.assertEqual(Gate(Flow(t,4),remote_channel_proved=True).decide(p),"REJECT")

    def test_same_5tuple_not_sufficient(self):
        p=Evidence("OWNED_PIPE",31,23,9)
        # There are deliberately no tuple/address fields in this admission gate.
        self.assertEqual(Gate(Flow(32,4),remote_channel_proved=True).decide(p),"REJECT")

    def test_missing_kernel_claim(self):
        self.assertEqual(Gate(Flow(31,4),wfp_claim=False,remote_channel_proved=True).decide(Evidence("OWNED_PIPE",31,23,9)),"REJECT")

    def test_wfp_or_ssh_loss(self):
        for kwargs in ({"wfp_alive":False},{"child_alive":False}):
            self.assertEqual(Gate(Flow(31,6),remote_channel_proved=True,**kwargs).decide(Evidence("OWNED_PIPE",31,23,9)),"REJECT")

    def test_pipe_generation_reuse(self):
        for generation in (8,10,900):
            self.assertEqual(Gate(Flow(31,4),generation=generation,remote_channel_proved=True).decide(Evidence("OWNED_PIPE",31,23,9)),"REJECT")

    def test_wrong_child_or_null_ownership(self):
        for child in (0,21,24):
            self.assertEqual(Gate(Flow(31,4),remote_channel_proved=True).decide(Evidence("OWNED_PIPE",31,child,9)),"REJECT")

    def test_udp_dns_quic_not_assumed(self):
        for proto in (17,136):
            self.assertEqual(Gate(Flow(31,6,proto),remote_channel_proved=True).decide(Evidence("OWNED_PIPE",31,23,9)),"REJECT")

    def test_witness_alone_not_native_windows_auth(self):
        # The hypothetical remote proof switch isn't a real OpenSSH API.
        local=Gate(Flow(31,4))
        self.assertNotEqual(local.decide(Evidence("OWNED_PIPE",31,23,9)),"CONDITIONAL_RELEASE")

    def test_non_mutating(self):
        g=Gate(Flow(31,4),remote_channel_proved=True)
        before=g.__dict__.copy()
        self.assertEqual(g.decide(Evidence("OWNED_PIPE",31,23,9)),"CONDITIONAL_RELEASE")
        self.assertEqual(g.__dict__,before)

    def test_source_pin_broker_no_upstream_ssh_credential(self):
        """Pinned raw source snapshots are from the specified GitHub blobs.

        Optional; executes only when exact source snapshots have been supplied,
        never silently assumes an unrelated local checkout is the target.
        """
        root=pathlib.Path(__file__).with_name("source_pins")
        if not root.exists():
            self.skipTest("exact GitHub source pins not staged")
        pins={
            "broker.rs":"825cb0a053dca0259a81fe77cdad9227c71883ae",
            "broker_windows.rs":"f315d2cfab16ed7474446a9bb819980c8c737163",
            "transport.rs":"414458795896f02ac7f6c92ec5f455b9268551e4",
        }
        for name,sha in pins.items():
            b=(root/name).read_bytes();hdr=f"blob {len(b)}\0".encode()
            self.assertEqual(hashlib.sha1(hdr+b).hexdigest(),sha)
        broker=(root/"broker.rs").read_text()
        bw=(root/"broker_windows.rs").read_text()
        transport=(root/"transport.rs").read_text()
        self.assertIn("--serve-research",broker)
        self.assertIn("ssh_port:u16",broker)
        self.assertIn("claim_and_connect(&d,ssh_port)",broker)
        self.assertIn("connect(s.0,",bw)
        self.assertIn("ip:[127,0,0,1]",bw)
        self.assertIn("crate::transport::socks_connect(&mut self.upstream",bw)
        self.assertIn("s.write_all(&[5,1,0])",transport)
        self.assertIn("response!=[5,0]",transport)
        # These surface checks are not an exhaustive absence-of-code proof.
        self.assertNotIn("GetExtendedTcpTable",bw)
        self.assertNotIn("GetNamedPipeServerProcessId",bw)

if __name__=="__main__":
    unittest.main(verbosity=2)
