"""R192: bounded synthetic replay of R19 CONNECT_REDIRECT callback decision order.

Read-only: no sockets, BFE calls, drivers, filters or system changes.
The model deliberately treats everything after the early AppId gate as UNKNOWN.
"""
import csv
import io
import itertools
import pathlib
import sys
import unittest

FIELDS = ('family', 'policy_live', 'selected', 'configured', 'route_matches', 'writable', 'armed', 'process_live', 'ssh_alive', 'outcome')


def verdict(family, policy_live, selected, configured, route_matches, writable, armed, process_live=True, ssh_alive=True):
    if not policy_live:
        return 'NO_FILTER_UNKNOWN'
    if not selected:
        return 'OUT_OF_SCOPE'
    if not configured:
        return 'BLOCK_BEFORE_APPID'
    if not writable:
        return 'PRIOR_ACTION_UNKNOWN'
    # kernel-r19/kernel/src/lib.rs initializes writable classifyOut to CONTINUE.
    # kernel-r19/kernel/src/redirect.rs returns without setting an action when
    # AppId selected by the BFE policy differs from the independently armed name.
    if not route_matches:
        return 'CONTINUE_NO_READY_CHECK'
    if not armed:
        return 'BLOCK_AFTER_READY_CHECK'
    return 'REQUIRES_NATIVE_PROOF'


def matrix():
    for family, policy_live, selected, configured, route_matches, writable, armed, process_live, ssh_alive in itertools.product(
        ('v4', 'v6'), (False, True), (False, True), (False, True),
        (False, True), (False, True), (False, True), (False, True),
        (False, True)
    ):
        yield (family, int(policy_live), int(selected), int(configured), int(route_matches),
               int(writable), int(armed), int(process_live), int(ssh_alive),
               verdict(family, policy_live, selected, configured, route_matches, writable,
                       armed, process_live, ssh_alive))


def serialize():
    buf = io.StringIO(newline='')
    wr = csv.writer(buf, lineterminator='\n')
    wr.writerow(FIELDS)
    wr.writerows(matrix())
    return buf.getvalue()


def source_guard(repo_root):
    root = pathlib.Path(repo_root) / 'research' / 'wfp-ale' / 'kernel-r19'
    kernel = (root / 'kernel' / 'src' / 'lib.rs').read_text(encoding='utf-8')
    redirect = (root / 'kernel' / 'src' / 'redirect.rs').read_text(encoding='utf-8')
    policy = (root / 'policy_windows.rs').read_text(encoding='utf-8')
    entry = kernel.split('unsafe extern "C" fn classify(', 1)[1].split('unsafe extern "C" fn auth_callback(', 1)[0]
    body = redirect.split('pub unsafe fn classify(', 1)[1].split('pub unsafe fn auth_classify(', 1)[0]
    begin = entry.find('(*out).actionType=k::FWP_ACTION_CONTINUE;')
    delegate = entry.find('redirect::classify(values,meta,_context,_filter,out);')
    mismatch = body.find('if appid!=&r.name[..r.len]{return;}')
    ready = body.find('if !ready(time){None}else{')
    if min(begin, delegate, mismatch, ready) < 0 or begin >= delegate or mismatch >= ready:
        raise RuntimeError('R19 contract changed; re-analyze, do not reuse R192 matrix')
    if 'FWPM_CONDITION_ALE_APP_ID' not in policy or 'FWP_ACTION_CALLOUT_UNKNOWN' not in policy:
        raise RuntimeError('R19 policy scope/action changed; re-analyze')
    return True


class NegativeTests(unittest.TestCase):
    def test_both_families_route_mismatch_skips_ready(self):
        for family in ('v4', 'v6'):
            for armed in (False, True):
                self.assertEqual(verdict(family, True, True, True, False, True, armed),
                                 'CONTINUE_NO_READY_CHECK')

    def test_matching_app_reaches_lease_gate(self):
        for family in ('v4', 'v6'):
            self.assertEqual(verdict(family, True, True, True, True, True, False),
                             'BLOCK_AFTER_READY_CHECK')

    def test_no_callback_no_leak_claim(self):
        self.assertEqual(verdict('v4', False, True, True, False, True, True),
                         'NO_FILTER_UNKNOWN')

    def test_no_write_right_no_leak_claim(self):
        self.assertEqual(verdict('v6', True, True, True, False, False, False),
                         'PRIOR_ACTION_UNKNOWN')

    def test_non_selected_not_attested(self):
        self.assertEqual(verdict('v4', True, False, True, False, True, True), 'OUT_OF_SCOPE')

    def test_unconfigured_blocks(self):
        self.assertEqual(verdict('v4', True, True, False, False, True, True),
                         'BLOCK_BEFORE_APPID')

    def test_matrix_size_and_strong_signal(self):
        records = list(matrix())
        self.assertEqual(len(records), 512)
        bad = [r for r in records if r[-1] == 'CONTINUE_NO_READY_CHECK']
        self.assertEqual(len(bad), 16)
        self.assertEqual({r[0] for r in bad}, {'v4', 'v6'})
        self.assertEqual({r[6] for r in bad}, {0, 1})


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--matrix':
        sys.stdout.write(serialize())
    elif len(sys.argv) == 3 and sys.argv[1] == '--source':
        source_guard(sys.argv[2]); print('R19_SOURCE_CONTRACT_MATCH')
    else:
        unittest.main()
