"""R77 independent stdlib oracle. Synthetic IOCTL results, NO Windows interaction."""
import hashlib
import itertools
import json
import unittest

CAP = 65536
MAX = 1048576
STATES = ('SUCCESS', 'INSUFFICIENT', 'EINVAL', 'NOTCONN', 'PENDING', 'UNSUPPORTED', 'NETDOWN')
REQUIRED = (0, 4, CAP, CAP + 1, MAX, MAX + 1)
LENGTHS = (0, 4, CAP, CAP + 1)
SECOND = ('SUCCESS', 'INSUFFICIENT', 'EINVAL', 'PENDING', 'SOCKET_SWAP')


def judge(family, status, required, size, socket_owned, context_valid, second):
    assert family in (4, 6)
    if not socket_owned:
        return 'REJECT_DIFFERENT_SOCKET'
    if not context_valid:
        return 'REJECT_BAD_CONTEXT'
    if status == 'SUCCESS':
        return 'CANDIDATE_NOT_PROOF' if 0 < size <= CAP else 'REJECT_BAD_LENGTH'
    if status != 'INSUFFICIENT':
        return 'REJECT_UNVERIFIABLE_ERROR'
    if not CAP < required <= MAX:
        return 'REJECT_INVALID_REQUIRED_LENGTH'
    if second == 'SOCKET_SWAP':
        return 'REJECT_DIFFERENT_SOCKET'
    if second != 'SUCCESS':
        return 'REJECT_RETRY_FAILED'
    return 'CANDIDATE_NOT_PROOF' if 0 < size <= required else 'REJECT_BAD_LENGTH'


def worlds():
    for world in itertools.product((4, 6), STATES, REQUIRED, LENGTHS,
                                   (False, True), (False, True), SECOND):
        yield world


def oracle():
    digest = hashlib.sha256()
    counts = {}
    for world in worlds():
        result = judge(*world)
        counts[result] = counts.get(result, 0) + 1
        digest.update((result + '\n').encode('ascii'))
    return {'cases': sum(counts.values()), 'counts': dict(sorted(counts.items())), 'sha256': digest.hexdigest()}


class ContractTests(unittest.TestCase):
    def check(self, expect, *, status='SUCCESS', required=0, size=4, socket=True,
              context=True, second='SUCCESS', family=4):
        self.assertEqual(judge(family, status, required, size, socket, context, second), expect)

    def test_nominal_is_only_candidate(self):
        self.check('CANDIDATE_NOT_PROOF')

    def test_ipv6_candidate(self):
        self.check('CANDIDATE_NOT_PROOF', family=6)

    def test_zero_length_never_succeeds(self):
        self.check('REJECT_BAD_LENGTH', size=0)

    def test_overreport_never_succeeds(self):
        self.check('REJECT_BAD_LENGTH', size=CAP+1)

    def test_no_zero_output_probe(self):
        self.check('REJECT_UNVERIFIABLE_ERROR', status='EINVAL', required=0, size=0)

    def test_ambiguous_einval_nonzero_hint_never_retries(self):
        self.check('REJECT_UNVERIFIABLE_ERROR', status='EINVAL', required=CAP+1)

    def test_insufficient_bounded_retry(self):
        self.check('CANDIDATE_NOT_PROOF', status='INSUFFICIENT', required=CAP+1, size=CAP+1)

    def test_insufficient_without_growth(self):
        self.check('REJECT_INVALID_REQUIRED_LENGTH', status='INSUFFICIENT', required=CAP)

    def test_insufficient_over_budget(self):
        self.check('REJECT_INVALID_REQUIRED_LENGTH', status='INSUFFICIENT', required=MAX+1)

    def test_retry_must_succeed(self):
        self.check('REJECT_RETRY_FAILED', status='INSUFFICIENT', required=CAP+1, second='PENDING')

    def test_socket_swap(self):
        self.check('REJECT_DIFFERENT_SOCKET', status='INSUFFICIENT', required=CAP+1, second='SOCKET_SWAP')

    def test_context_fails(self):
        self.check('REJECT_BAD_CONTEXT', context=False)

    def test_socket_ownership_fails(self):
        self.check('REJECT_DIFFERENT_SOCKET', socket=False)

    def test_unsupported_provider(self):
        self.check('REJECT_UNVERIFIABLE_ERROR', status='UNSUPPORTED')

    def test_network_down(self):
        self.check('REJECT_UNVERIFIABLE_ERROR', status='NETDOWN')

    def test_pending_cannot_claim(self):
        self.check('REJECT_UNVERIFIABLE_ERROR', status='PENDING')


if __name__ == '__main__':
    import sys
    if '--oracle' in sys.argv:
        print(json.dumps(oracle(), sort_keys=True))
    else:
        unittest.main()
