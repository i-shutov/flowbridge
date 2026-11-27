"""Synthetic parser negatives, not native G2 acceptance."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import g2_etw_owner_probe as probe
from g2_etw_owner_probe import (
    CORRELATION, DENIED, KERNEL_NETWORK, MAX_XML, PinnedOwner,
    ProbeDiagnostics, ProbeFailure, audit_xml, ticks,
)

CREATED = ticks('2026-11-06T20:00:00.1234567Z')
STOPPED = ticks('2026-11-06T20:00:04.0000000Z')
OWNERS = [PinnedOwner(110 + i, CREATED, 4 if i < 2 else 6, 43000 + i) for i in range(4)]
LOSSLESS = 'Buffers Processed 4\nTotal Events  Lost      0\nTotal Events  20\n'


def event(owner, *, provider=KERNEL_NETWORK, when='2026-11-06T20:00:01.1234567Z'):
    e = ET.Element('Event')
    s = ET.SubElement(e, 'System')
    ET.SubElement(s, 'Provider', Guid='{' + provider + '}')
    ET.SubElement(s, 'EventID').text = '12' if owner.family == 4 else '28'
    ET.SubElement(s, 'TimeCreated', SystemTime=when)
    # Deliberately wrong header PID: only the kernel payload may bind owner.
    ET.SubElement(s, 'Execution', ProcessID='900001', ThreadID='900002')
    ET.SubElement(s, 'Correlation', ActivityID='{11111111-1111-1111-1111-111111111111}',
                  RelatedActivityID='{22222222-2222-2222-2222-222222222222}')
    data = ET.SubElement(e, 'EventData')
    for name, value in {'PID': str(owner.pid), 'daddr': '127.0.0.1' if owner.family == 4 else '::1',
                        'dport': str(owner.port), 'connid': hex(10000 + owner.pid)}.items():
        ET.SubElement(data, 'Data', Name=name).text = value
    return e


def document(events=None):
    root = ET.Element('Events')
    root.extend([event(o) for o in OWNERS] if events is None else events)
    return ET.tostring(root, encoding='utf-8')


class KernelOwnerAuditTests(unittest.TestCase):
    def check_rejected(self, raw, code, *, summary=LOSSLESS, owners=OWNERS):
        with self.assertRaisesRegex(ProbeFailure, '^' + code + '$'):
            audit_xml(raw, summary, owners, STOPPED)

    def test_exact_dual_stack_payloads_with_wrong_header_pid(self):
        report = audit_xml(document(), LOSSLESS, OWNERS, STOPPED)
        self.assertTrue(report['ok'])
        self.assertTrue(report['payload_pid_used_not_header_pid'])
        self.assertEqual(report['independent_clients'], 4)
        self.assertEqual(report['ipv4_client_owners_verified'], 2)
        self.assertEqual(report['ipv6_client_owners_verified'], 2)
        self.assertTrue(all(report[k] is False for k in DENIED))
        self.assertFalse(report['etw_to_ndisrd_delivery_token_available'])

    def test_header_pid_never_substitutes_missing_payload(self):
        events = [event(o) for o in OWNERS]
        for e, o in zip(events, OWNERS):
            e.find('System/Execution').set('ProcessID', str(o.pid))
            data = e.find('EventData')
            data.remove(data.find("Data[@Name='PID']"))
        self.check_rejected(document(events), 'kernel_payload_owner_evidence_incomplete')

    def test_incomplete_trace_retains_only_bounded_match_counts(self):
        diagnostics = ProbeDiagnostics()
        events = [event(o) for o in OWNERS]
        data = events[0].find('EventData')
        data.remove(data.find("Data[@Name='PID']"))
        with self.assertRaisesRegex(ProbeFailure, '^kernel_payload_owner_evidence_incomplete$'):
            audit_xml(document(events), LOSSLESS, OWNERS, STOPPED, diagnostics)
        self.assertEqual(diagnostics.phase, 'kernel_owner_match')
        self.assertEqual(diagnostics.kernel_network_events, 4)
        self.assertEqual(diagnostics.kernel_tcp_connect_events, 4)
        self.assertEqual(diagnostics.complete_connect_payloads, 3)
        self.assertEqual(diagnostics.connect_payloads_for_pinned_clients, 3)
        self.assertEqual(diagnostics.verified_client_owners, 3)

    def test_missing_and_zero_connids_counted_without_minting_owners(self):
        diagnostics = ProbeDiagnostics()
        events = [event(o) for o in OWNERS]
        data = events[0].find('EventData')
        data.remove(data.find("Data[@Name='connid']"))
        for item in (events[1], events[2]):
            item.find("EventData/Data[@Name='connid']").text = '0'
        with self.assertRaisesRegex(ProbeFailure, '^kernel_connection_id_missing$'):
            audit_xml(document(events), LOSSLESS, OWNERS, STOPPED, diagnostics)
        self.assertEqual(diagnostics.connect_events_without_connid, 1)
        self.assertEqual(diagnostics.ipv4_matches_with_zero_connid, 1)
        self.assertEqual(diagnostics.ipv6_matches_with_zero_connid, 1)
        self.assertEqual(diagnostics.ipv4_matches_with_nonzero_connid, 0)
        self.assertEqual(diagnostics.ipv6_matches_with_nonzero_connid, 1)
        self.assertEqual(diagnostics.verified_client_owners, 1)

    def test_failed_trace_start_preserves_reason_when_cleanup_cannot_confirm(self):
        diagnostics = ProbeDiagnostics()
        os_stub = SimpleNamespace(name='nt', environ={
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
        })
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('logman', 'tracerpt', 'curl'):
                (root / (name + '.exe')).touch()
            with patch.object(probe, 'os', os_stub), \
                    patch.object(probe, 'Windows', return_value=SimpleNamespace(root=root)), \
                    patch.object(probe.subprocess, 'run', return_value=SimpleNamespace(returncode=1)) as run:
                with self.assertRaisesRegex(ProbeFailure, '^etw_session_start_failed$'):
                    probe.native_probe(diagnostics)
        operations = [call.args[0][1] for call in run.call_args_list]
        self.assertEqual(operations, ['create', 'stop'])
        self.assertEqual(diagnostics.phase, 'trace_start')
        self.assertIs(diagnostics.owned_cleanup_verified, False)
        self.assertIs(diagnostics.private_trace_cleanup_verified, True)

    def test_unexpected_exception_prints_no_raw_detail_or_packet_authority(self):
        with TemporaryDirectory() as temp, StringIO() as stream, redirect_stdout(stream):
            output = Path(temp) / 'sanitized.json'
            with patch.object(probe, 'native_probe', side_effect=OSError('secret/raw-path')):
                self.assertEqual(probe.main(['--consent', probe.CONSENT, '--output', str(output)]), 1)
            shown = stream.getvalue()
            report = json.loads(output.read_bytes())
        self.assertNotIn('secret/raw-path', shown)
        self.assertIn('G2_ETW_CONNECTION_EVIDENCE=FAIL', shown)
        self.assertIn('G2_PACKET_BOUND=UNPROVED', shown)
        self.assertIn('"error_code": "unexpected_collector_failure"', shown)
        self.assertTrue(all(report[key] is False for key in DENIED))

    def test_manual_mode_refuses_win10_before_opening_windows_tools(self):
        os_stub = SimpleNamespace(name='nt', environ={
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'self-hosted',
            'GITHUB_EVENT_NAME': 'workflow_dispatch',
        })
        sys_stub = SimpleNamespace(
            getwindowsversion=lambda: SimpleNamespace(product_type=1, build=19045),
        )
        with patch.object(probe, 'os', os_stub), \
                patch.object(probe, 'sys', sys_stub), \
                patch.object(probe.socket, 'gethostname', return_value='VM-326272'), \
                patch.object(probe, 'Windows') as windows:
            with self.assertRaisesRegex(ProbeFailure, '^requires_windows_11_client$'):
                probe.native_probe(ProbeDiagnostics(), 'VM-326272')
            windows.assert_not_called()

    def test_wrong_provider_cannot_mint_owner(self):
        self.check_rejected(document([event(o, provider=CORRELATION) for o in OWNERS]),
                            'kernel_payload_owner_evidence_incomplete')

    def test_reused_pid_before_epoch_rejected(self):
        events = [event(o) for o in OWNERS]
        events[0] = event(OWNERS[0], when='2026-11-06T19:59:59.9999999Z')
        self.check_rejected(document(events), 'pid_epoch_or_trace_interval_mismatch')

    def test_event_after_trace_close_rejected(self):
        events = [event(o) for o in OWNERS]
        events[0] = event(OWNERS[0], when='2026-11-06T20:00:04.0000001Z')
        self.check_rejected(document(events), 'pid_epoch_or_trace_interval_mismatch')

    def test_loss_and_unknown_loss_accounting_never_pass(self):
        for summary, code in [('Total Events Lost 1', 'trace_events_lost'),
                              ('unknown', 'trace_loss_accounting_missing_or_ambiguous'),
                              ('Total Events Lost 0\nTotal Events Lost 0',
                               'trace_loss_accounting_missing_or_ambiguous')]:
            with self.subTest(summary=summary):
                self.check_rejected(document(), code, summary=summary)

    def test_ambiguous_payload_duplicate_rejected(self):
        events = [event(o) for o in OWNERS]
        ET.SubElement(events[0].find('EventData'), 'Data', Name='PID').text = str(OWNERS[0].pid)
        self.check_rejected(document(events), 'duplicate_event_payload_field')

    def test_sibling_tuple_family_and_missing_evidence(self):
        events = [event(o) for o in OWNERS]
        events[0].find("EventData/Data[@Name='dport']").text = str(OWNERS[1].port)
        self.check_rejected(document(events), 'kernel_payload_owner_evidence_incomplete')
        events = [event(o) for o in OWNERS]
        events[2].find("EventData/Data[@Name='daddr']").text = '127.0.0.1'
        self.check_rejected(document(events), 'kernel_payload_owner_evidence_incomplete')
        self.check_rejected(document(events[:3]), 'kernel_payload_owner_evidence_incomplete')

    def test_wrong_pid_cannot_borrow_owners_record(self):
        events = [event(o) for o in OWNERS]
        events[0].find("EventData/Data[@Name='PID']").text = str(OWNERS[1].pid)
        self.check_rejected(document(events), 'kernel_payload_owner_evidence_incomplete')

    def test_empty_or_non_numeric_pid_and_unknown_endpoint_schema(self):
        for field, value, code in [('PID', '-1', 'invalid_integer_payload'),
                                   ('dport', '443abc', 'invalid_integer_payload'),
                                   ('daddr', '0x0100007f', 'destination_schema_unsupported')]:
            events = [event(o) for o in OWNERS]
            events[0].find(f"EventData/Data[@Name='{field}']").text = value
            self.check_rejected(document(events), code)

    def test_dtd_malformed_and_bounded_xml(self):
        self.check_rejected(b'<!DOCTYPE x><Events/>', 'trace_xml_dtd')
        self.check_rejected(b'<!DOCTYPE x><Events/>'.decode().encode('utf-16'), 'trace_xml_dtd')
        self.check_rejected(b'<broken', 'trace_xml_invalid')
        self.check_rejected(b'', 'trace_xml_size')
        self.check_rejected(b' ' * (MAX_XML + 1), 'trace_xml_size')

    def test_duplicate_or_invalid_pinned_owner_fail(self):
        self.check_rejected(document(), 'independent_owner_set_invalid', owners=[OWNERS[0]] * 4)
        bad = [PinnedOwner(0, CREATED, 4, 43000), *OWNERS[1:]]
        self.check_rejected(document(), 'pinned_owner_invalid', owners=bad)
        bad = [PinnedOwner(110, STOPPED, 4, 43000), *OWNERS[1:]]
        self.check_rejected(document(), 'owner_created_after_trace', owners=bad)

    def test_connection_identity_and_event_class_cannot_be_substituted(self):
        for invalid_id in ('42', '0', ''):
            events = [event(o) for o in OWNERS]
            events[0].find('System/EventID').text = invalid_id
            self.check_rejected(document(events), 'kernel_payload_owner_evidence_incomplete')
        events = [event(o) for o in OWNERS]
        events[0].find("EventData/Data[@Name='connid']").text = '0'
        self.check_rejected(document(events), 'kernel_connection_id_missing')
        events = [event(o) for o in OWNERS]
        events[1].find("EventData/Data[@Name='connid']").text = hex(10000 + OWNERS[0].pid)
        self.check_rejected(document(events), 'kernel_connection_owner_ambiguous')

    def test_report_contains_no_identity_or_address(self):
        report = audit_xml(document(), LOSSLESS, OWNERS, STOPPED)
        self.assertTrue({'pid', 'path', 'local', 'remote', 'port'}.isdisjoint(report))
        serialized = json.dumps(report)
        for private in ('127.0.0.1', '::1', '900001', '43000', str(CREATED), 'process_path'):
            self.assertNotIn(private, serialized)

    def test_xml_datetime_offsets_preserve_actual_utc_without_rounding(self):
        for value in ('2026-11-06T20:00:00.123456700+00:00',
                      '2026-11-06T23:00:00.1234567+03:00',
                      '2026-11-06T15:00:00.1234567-0500'):
            self.assertEqual(ticks(value), CREATED)
        for value in ('2026-11-06T20:00:00.1234567',
                      '2026-11-06T20:00:00+00:99',
                      '2026-11-06T20:00:00+15:00'):
            with self.assertRaises(ProbeFailure):
                ticks(value)
        events = [event(o, when='2026-11-06T23:00:01.123456700+03:00') for o in OWNERS]
        self.assertTrue(audit_xml(document(events), LOSSLESS, OWNERS, STOPPED)['ok'])

    def test_filetime_precision_and_namespaced_xml(self):
        self.assertEqual(ticks('2026-11-06T20:00:00.123456700Z'), CREATED)
        self.assertEqual(ticks('1601-01-01T00:00:00.0000001Z'), 1)
        with self.assertRaises(ProbeFailure):
            ticks('2026-11-06T20:00:00.123456789Z')
        root = ET.fromstring(document())
        for node in root.iter():
            node.tag = '{http://schemas.microsoft.com/win/2004/08/events/event}' + node.tag
        self.assertTrue(audit_xml(ET.tostring(root), LOSSLESS, OWNERS, STOPPED)['ok'])


if __name__ == '__main__':
    unittest.main()
