#!/usr/bin/env python3
"""Independent finite negative oracle for R221. Pure Python stdlib, no OS probes."""
import hashlib
import itertools
import unittest


def worlds():
    for bits in itertools.product((0, 1), repeat=8):
        yield bits


def classify(bits):
    family, selected, redirected, endpoint, veto, broker, context, receipt = bits
    auth = bool(selected and redirected and endpoint)
    # Distinct abstractions: the final layer decision is after all sublayers.
    final = bool(auth and not veto)
    raw = bool(auth and broker and context)  # hypothetical raw context availability
    typed = bool(raw and final and receipt)
    return (int(auth), int(final), int(raw), int(typed))


def output():
    return ''.join(','.join(map(str, bits + classify(bits))) + '\n' for bits in worlds())


class R221(unittest.TestCase):
    def test_two_families_same_candidate_later_veto(self):
        for f in (0, 1):
            good = (f, 1, 1, 1, 0, 1, 1, 1)
            veto = (f, 1, 1, 1, 1, 1, 1, 0)
            self.assertEqual(classify(good), (1, 1, 1, 1))
            self.assertEqual(classify(veto), (1, 0, 1, 0))

    def test_kernel_claim_candidate_not_final_result(self):
        for bits in worlds():
            auth, final, raw, typed = classify(bits)
            self.assertTrue(typed <= final <= auth)
            self.assertTrue(typed <= raw)
        self.assertTrue(any(classify(x)[2] and not classify(x)[1] for x in worlds()))

    def test_no_raw_claim_without_exact_context_or_broker(self):
        for bits in worlds():
            if not bits[5] or not bits[6]:
                self.assertEqual(classify(bits)[2], 0)

    def test_no_auth_on_direct_or_endpoint_aba(self):
        for bits in worlds():
            if not bits[2] or not bits[3]:
                self.assertEqual(classify(bits)[0], 0)

    def test_later_veto_change_is_visible(self):
        for f in (0, 1):
            a=(f, 1, 1, 1, 0, 1, 1, 1)
            b=(f, 1, 1, 1, 1, 1, 1, 1)
            self.assertEqual(classify(a)[0], classify(b)[0])
            self.assertNotEqual(classify(a)[1], classify(b)[1])

    def test_all_256_worlds(self):
        self.assertEqual(len(list(worlds())), 256)
        self.assertEqual(len(output().splitlines()), 256)


if __name__ == '__main__':
    import sys
    if '--matrix' in sys.argv:
        print(output(), end='')
    elif '--summary' in sys.argv:
        rows=[classify(w) for w in worlds()]
        print('cases=256', 'auth=' + str(sum(x[0] for x in rows)),
              'final=' + str(sum(x[1] for x in rows)),
              'raw=' + str(sum(x[2] for x in rows)),
              'typed=' + str(sum(x[3] for x in rows)),
              'raw_but_final_block=' + str(sum(x[2] and not x[1] for x in rows)),
              'sha256=' + hashlib.sha256(output().encode()).hexdigest())
    else:
        unittest.main()
