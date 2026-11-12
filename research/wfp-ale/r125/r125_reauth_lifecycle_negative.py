#!/usr/bin/env python3
"""R125: synthetic negative audit of one-use R19 AUTH lifecycle. No WFP/network calls.

The pure state machine deliberately treats the WFP indications as hypothetical.
It must never be used to infer that a native WFP classify occurred.
"""
import argparse
import hashlib
import itertools
import json
import pathlib
import sys
import unittest

PHASES = ('issued', 'authed', 'claimed', 'retired')
SOURCE_BLOBS = {
    'kernel-r19/kernel/src/redirect.rs': '9a07e026134d46ef646d39862bd982cc48bbc5f6',
    'kernel-r19/kernel/src/handoff.rs': 'e1d17217db50362ba9c4efc83af820b6beb094cf',
}

def source_attestation(root):
    for rel, expected in SOURCE_BLOBS.items():
        src = pathlib.Path(root, rel).read_bytes()
        observed = hashlib.sha1(b'blob ' + str(len(src)).encode() + b'\0' + src).hexdigest()
        assert observed == expected, (rel, observed, expected)
        s = src.decode('utf-8')
        if rel.endswith('redirect.rs'):
            assert 'bits & (0x0000_0004|0x0200_0000)!=0{return false;}' in s
            assert 'route.book.attest(identity,original_destination,now())' in s
        else:
            assert 'if slot.auth_seen || now<when || now-when>TTL{return false;}' in s
            assert 's.live=false; // terminal even on failed, unauthenticated or replayed claim' in s
    return SOURCE_BLOBS

def evaluate(phase, family, protocol, bits):
    # All 8 binary values are independently varied; no source ticket is forged.
    reauth, redirected, honoring, metadata, identity, destination, lease, ttl = \
        ((bits >> index) & 1 for index in range(8))
    scope = protocol == 6 and family in (4, 6)
    pre = bool(scope and redirected and not honoring and metadata and identity and destination and lease and ttl)
    # R19 auth_check rejects REAUTHORIZE before touching Book::attest.
    actual = bool(pre and not reauth and phase == 'issued')
    # Counterfactual 1: remove ONLY the REAUTHORIZE flag predicate.
    without_flag = bool(pre and phase == 'issued')
    # Counterfactual 2: remove flag predicate AND allow auth_seen reset,
    # but keep one-shot claim consumption (live=false).
    without_flag_and_auth_reset = bool(pre and phase in ('issued', 'authed'))
    return int(actual), int(without_flag), int(without_flag_and_auth_reset)

def matrix():
    for phase, family, protocol, bits in itertools.product(PHASES, (4, 6), (6, 17), range(256)):
        result = evaluate(phase, family, protocol, bits)
        yield '|'.join(map(str, (phase, family, protocol, bits, *result)))

def digest():
    lines = list(matrix())
    return {'cases': len(lines), 'sha256': hashlib.sha256(('\n'.join(lines)+'\n').encode()).hexdigest(),
            'native_admitted': sum(int(s.split('|')[-3]) for s in lines),
            'without_flag_admitted': sum(int(s.split('|')[-2]) for s in lines),
            'without_flag_and_auth_reset_admitted': sum(int(s.split('|')[-1]) for s in lines)}

class Regression(unittest.TestCase):
    def test_initial_only_if_all_guards_valid(self):
        good = 0b11111010  # reauth=0, redirected=1, honoring=0, all remaining 5 bits=1
        self.assertEqual(evaluate('issued', 4, 6, good), (1, 1, 1))
        for bit in range(8):
            if bit == 0:
                self.assertEqual(evaluate('issued', 4, 6, good | 1), (0, 1, 1))
            elif bit == 2:
                self.assertEqual(evaluate('issued', 4, 6, good | (1<<2)), (0, 0, 0))
            else:
                self.assertEqual(evaluate('issued', 4, 6, good ^ (1<<bit)), (0, 0, 0))
    def test_reauthorize_before_claim(self):
        # Flag denial plus non-repeatable auth_seen latch.
        self.assertEqual(evaluate('authed', 4, 6, 0b11111011), (0, 0, 1))
    def test_reauthorize_after_claim(self):
        # Already-claimed ticket: even changing two checks cannot restore it.
        self.assertEqual(evaluate('claimed', 6, 6, 0b11111011), (0, 0, 0))
    def test_both_family_protocol_scope(self):
        self.assertEqual(evaluate('issued', 6, 6, 0b11111010), (1, 1, 1))
        self.assertEqual(evaluate('issued', 6, 17, 0b11111010), (0, 0, 0))
    def test_lost_ssh_or_no_metadata(self):
        for bit in (3, 6, 7):
            self.assertEqual(evaluate('issued', 4, 6, 0b11111010 ^ (1<<bit)), (0, 0, 0))
    def test_retired_ticket_remains_dead(self):
        for b in (0b11111010, 0b11111011):
            self.assertEqual(evaluate('retired', 4, 6, b), (0, 0, 0))
    def test_deterministic_coverage(self):
        self.assertEqual(digest()['cases'], 4096)
        self.assertEqual(digest()['native_admitted'], 2)
        self.assertEqual(digest()['without_flag_admitted'], 4)
        self.assertEqual(digest()['without_flag_and_auth_reset_admitted'], 8)

if __name__=='__main__':
    cli=argparse.ArgumentParser()
    cli.add_argument('--source-check', help='Path to research/wfp-ale with exact R19 source')
    cli.add_argument('--matrix', action='store_true')
    args=cli.parse_args()
    if args.source_check:
        print('attested_source_git_blobs=' + json.dumps(source_attestation(args.source_check),sort_keys=True))
    if args.matrix:
        print(json.dumps(digest(),sort_keys=True))
    else:
        result=unittest.main(argv=[sys.argv[0]],exit=False,verbosity=2)
        if not result.result.wasSuccessful(): sys.exit(1)
        print(json.dumps(digest(),sort_keys=True))
