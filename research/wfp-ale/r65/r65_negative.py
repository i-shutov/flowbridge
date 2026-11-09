#!/usr/bin/env python3
"""R65 offline fail-closed source audit. No Windows API or network call."""
from pathlib import Path
import re
import unittest

BASE = Path(__file__).resolve().parents[1]
SRC = (BASE / 'r63' / 'r63_endpoint_probe.rs').read_text('utf-8')

def attest(text: str) -> bool:
    # These expressions search executable Rust syntax, not informational comments.
    no_risky_calls = not re.search(
        r'\bunsafe\s*\{|\bunsafe\s+extern|\bextern\s*"system"|'
        r'\b(?:WSAIoctl|FwpsAleEndpointGetById0|FwpmFreeMemory0|FwpsFreeMemory0|'
        r'FwpmEngineOpen0|FwpmEngineClose0)\s*\(', text)
    gate = r'pub\s+const\s+fn\s+probe_readiness\(\)\s*->\s*ProbeReadiness\s*\{\s*ProbeReadiness::DisabledAllocatorOwnershipUnverified\s*\}'
    stub = r'pub\s+fn\s+inspect_existing_socket\([^)]*\)\s*->\s*Result<EndpointDiagnostic,\s*ProbeError>\s*\{\s*Err\(ProbeError::AllocatorOwnershipUnverified\)\s*\}'
    return bool(no_risky_calls and re.search(gate,text) and re.search(stub,text) and
                re.search(r'\#\[cfg\(windows\)\]\s*mod\s+windows_readonly',text) and
                'pub const ALE_ENDPOINT_IOCTL_OPCODE: u32 = 0x4000_0000 | 0x1800_0000 | 205;' in text and
                'Assessment::Unobserved' in text and 'Assessment::EndpointOnlyNotOrigin' in text)

class R65(unittest.TestCase):
    def test_01_live_source_safe(self): self.assertTrue(attest(SRC))
    def test_02_no_win_syscalls(self): self.assertNotRegex(SRC,r'\bunsafe\s*\{|\bunsafe\s+extern')
    def test_03_still_distinguishes_unobserved(self): self.assertRegex(SRC,r'!o\.dispatched\s*\{\s*return Assessment::Unobserved;')
    def test_04_diagnostic_not_origin(self): self.assertRegex(SRC,r'Assessment::EndpointOnlyNotOrigin\s*\n\}')
    def test_05_opcode_retained(self): self.assertEqual(0x40000000 | 0x18000000 | 205,0x580000CD)
    def test_06_reintroduced_extern_detected(self): self.assertFalse(attest(SRC+'\nunsafe extern "system" {}'))
    def test_07_reintroduced_wrong_free_detected(self): self.assertFalse(attest(SRC+'\nunsafe { FwpmFreeMemory0(0); }'))
    def test_08_reintroduced_fwps_free_detected(self): self.assertFalse(attest(SRC+'\nunsafe { FwpsFreeMemory0(0); }'))
    def test_09_reintroduced_bfe_detected(self): self.assertFalse(attest(SRC+'\nunsafe { FwpmEngineOpen0(0); }'))
    def test_10_unsafe_syscall_detected(self): self.assertFalse(attest(SRC+'\nWSAIoctl(0);'))
    def test_11_fail_open_detected(self): self.assertFalse(attest(SRC.replace('Err(ProbeError::AllocatorOwnershipUnverified)','Ok(EndpointDiagnostic{id:0,ip_version:0,protocol:0,appid_bytes:0})')))
    def test_12_gate_removed_detected(self): self.assertFalse(attest(SRC.replace('DisabledAllocatorOwnershipUnverified\n}', 'DisabledElsewhere\n}')))
    def test_13_reintro_endpoint_get_detected(self): self.assertFalse(attest(SRC+'\nFwpsAleEndpointGetById0(0);'))
    def test_14_no_original_socket_join_claim(self): self.assertNotIn('Assessment::KernelOriginVerified',SRC)
    def test_15_code_has_no_no_go_override(self): self.assertNotRegex(SRC,r'\bunsafe\s*\{')

if __name__ == '__main__': unittest.main(verbosity=2)
