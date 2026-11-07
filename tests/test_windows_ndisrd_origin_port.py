"""Local-only endpoint wiring regression; no PowerShell, NDISRD, SSH or FFI dispatch."""
from __future__ import annotations

import ast
import base64
import io
from pathlib import Path
import unittest
from unittest.mock import patch

from g1_controlled_origin import OriginSpec, REQUEST
import windows_external_powershell_lab as external
import windows_ndisrd_self_redirect as native


class ControlledDestinationTests(unittest.TestCase):
    def test_original_tuple_and_sshd_allowlist_use_one_nondefault_origin_endpoint(self):
        spec = OriginSpec('10.123.0.2', 18443, 'ab' * 16)
        self.assertEqual(native.controlled_destination(spec), '10.123.0.2:18443')
        tree = ast.parse(Path(native.__file__).read_text(encoding='utf-8'))
        targets = [node for node in ast.walk(tree) if isinstance(node, ast.Dict)
                   for key, value in zip(node.keys, node.values)
                   if isinstance(key, ast.Constant) and key.value == 'target'
                   and isinstance(value, ast.Name) and value.id == 'destination']
        self.assertEqual(len(targets), 1, 'Original TCP target must use the validated destination.')
        allowlists = [node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)
                      and any(isinstance(part, ast.Constant) and 'PermitOpen ' in str(part.value)
                              for part in node.values)]
        self.assertEqual(len(allowlists), 1)
        self.assertTrue(any(isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name)
                            and part.value.id == 'destination' for part in allowlists[0].values))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'ExternalPowerShellCanary']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0].args[-1]), 'origin.port')
        self.assertEqual(len(REQUEST), 57)

    def test_all_23_native_phases_and_evidence_gates_are_retained(self):
        source = Path(native.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source)
        assignments = {node.targets[0].id: node.value for node in ast.walk(tree)
                       if isinstance(node, ast.Assign) and len(node.targets) == 1
                       and isinstance(node.targets[0], ast.Name)
                       and node.targets[0].id in {'phases', 'sources'}}
        phases = ast.literal_eval(assignments['phases'])
        sources = ast.literal_eval(assignments['sources'])
        self.assertEqual(len(phases), 12)
        self.assertEqual(set(sources), {'self', 'rust-child', 'powershell', 'external-powershell'})
        self.assertEqual(len(phases) + 2 * len(sources) + 3, 23)
        for evidence in ('selected_original_frames_sent_to_adapter',
                         'external_sibling_socket_pid_epoch_consistent',
                         'external_process_exit_confirmed',
                         'native_owner_binding_accepted', 'rollback_confirmed'):
            self.assertIn(evidence, source)
        self.assertIn('not a DIRECT fallback', source)

    def test_independent_client_has_no_implicit_port_and_rejects_invalid_before_spawn(self):
        with self.assertRaises(TypeError):
            external.ExternalPowerShellCanary('10.123.0.1', '10.123.0.2')
        with patch.object(external, 'executable', side_effect=AssertionError('No signed client dispatch')):
            for value in (None, True, False, '18443', 18443.0, 0, -1, 65536):
                with self.subTest(port=value), self.assertRaisesRegex(AssertionError, 'explicit valid target port'):
                    external.ExternalPowerShellCanary('10.123.0.1', '10.123.0.2', value)
        for port in (1, 18443, 65535):
            self.assertEqual(external.ExternalPowerShellCanary('10.123.0.1', '10.123.0.2', port).target_port, port)

    def test_independent_powershell_environment_carries_explicit_origin_port(self):
        class FakeProcess:
            stdout = io.StringIO('')
            stopped = False
            pid = 12345
            def poll(self):return 0 if self.stopped else None
            def kill(self):self.stopped = True
            def wait(self, timeout):return 0
        process = FakeProcess()
        with patch.object(external, 'executable', return_value=Path('synthetic-signed-powershell.exe')), \
             patch.object(external, 'read_startup_line', return_value='{"source_port":32768,"control_port":32769}'), \
             patch.object(external.subprocess, 'CREATE_NO_WINDOW', 0, create=True), \
             patch.object(external.subprocess, 'Popen', return_value=process) as spawn:
            with external.ExternalPowerShellCanary('10.123.0.1', '10.123.0.2', 18443) as canary:
                self.assertEqual(canary.request(), {'pid':12345, 'source_port':32768, 'control_port':32769})
                kwargs = spawn.call_args.kwargs
                self.assertEqual(kwargs['env']['FLOWBRIDGE_LAB_TARGET_PORT'], '18443')
                command = spawn.call_args.args[0]
                script = base64.b64decode(command[-1]).decode('utf-16-le')
                self.assertIn('$port = [int]$env:FLOWBRIDGE_LAB_TARGET_PORT', script)
                self.assertIn('$s.Connect([System.Net.IPEndPoint]::new($target, $port))', script)
                self.assertIn("if ($reader.ReadLine() -cne 'ack')", script)
                self.assertIn('$s.Shutdown([System.Net.Sockets.SocketShutdown]::Send)', script)
        self.assertTrue(process.stopped)


if __name__ == '__main__':
    unittest.main()
