#!/usr/bin/env python3
"""Independent static source-bound witness checks; never compiles/loads code."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
RUST = (ROOT / 'r72_win_process_readonly.rs').read_text()

class Scope(unittest.TestCase):
    def test_whitelist_only_observational_win_api(self):
        funcs = set(re.findall(r'\bfn\s+([A-Za-z0-9_]+)\(', RUST))
        win = {x for x in funcs if x[:1].isupper()}
        self.assertEqual(win, {'GetCurrentProcessId', 'OpenProcess', 'CloseHandle',
                               'GetProcessTimes','QueryFullProcessImageNameW',
                               'FwpmGetAppIdFromFileName0','FwpmFreeMemory0'})

    def test_no_wfp_activation_or_kernel_integration(self):
        for forbidden in ('FwpmEngineOpen', 'FwpmFilterAdd', 'FwpsCalloutRegister',
                          'DeviceIoControl', 'WSAIoctl', 'CreateService', 'StartService',
                          'SetWindowsHookEx', 'SeDebugPrivilege('):
            self.assertNotIn(forbidden,RUST)

    def test_declares_observational_limits(self):
        for label in ('proof_of_original_ale_owner=false', 'proof_of_accepted_socket=false',
                      'proof_of_no_direct=false'):
            self.assertIn(label,RUST)

    def test_read_only_process_access(self):
        self.assertIn('const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000',RUST)
        self.assertIn('OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid)',RUST)

    def test_no_user_supplied_path_unsafe_io(self):
        self.assertIn('QueryFullProcessImageNameW(handle.0,0,chars.as_mut_ptr(),&mut n)',RUST)
        self.assertIn('FwpmGetAppIdFromFileName0(wide.as_ptr(),&mut blob)',RUST)

if __name__=='__main__': unittest.main(verbosity=2)
