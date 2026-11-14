#!/usr/bin/env python3
"""R194: pure deterministic model of the R19 AUTH filter/callback scope.

No Windows APIs, sockets, WFP policy mutation or packets. It models an explicit
hypothesis: outbound broker socket carries WFP redirect records and preserves
ALE_ORIGINAL_APP_ID of the selected source. Documentation supports this field
semantics, but the live per-leg callback sequence is NOT measured.
"""
import csv
import io
import itertools
import sys
import unittest

FIELDS = ("family", "leg", "tcp", "original_selected", "current_is_broker",
          "records_set", "honoring", "ticket_valid", "route_ready")
LEGS = ("direct_client", "redirected_client", "proxy_egress")


def verdict(c):
    # The exact R19 BFE filter matches ALE_ORIGINAL_APP_ID + TCP only.
    if not (c["tcp"] and c["original_selected"]):
        return "UNMATCHED_OUTSIDE_FILTER"
    # Simplified R19 auth_check; other mandatory metadata is assumed valid
    # only for the redirected client leg. Egress is not the local proxy target.
    if (c["leg"] == "redirected_client" and not c["honoring"]
            and c["ticket_valid"] and c["route_ready"]):
        return "PERMIT_CANDIDATE_NOT_NATIVE_PROOF"
    return "BLOCK_IF_R19_CALLBACK_RUNS"


def cases():
    for family in (4, 6):
        for leg in LEGS:
            for bits in itertools.product((0, 1), repeat=7):
                yield dict(zip(FIELDS, (family, leg, *bits)))


def matrix():
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow((*FIELDS, "r19_model_verdict"))
    for c in cases():
        writer.writerow((*(c[k] for k in FIELDS), verdict(c)))
    return out.getvalue()


def example(leg="proxy_egress", **kwargs):
    c = dict(family=4, leg=leg, tcp=1, original_selected=1,
             current_is_broker=1, records_set=1, honoring=0,
             ticket_valid=1, route_ready=1)
    c.update(kwargs)
    return c


class AuthScopeTests(unittest.TestCase):
    def test_proxy_outbound_with_original_appid_hits_filter_then_block(self):
        for family in (4, 6):
            c = example(family=family)
            self.assertEqual(verdict(c), "BLOCK_IF_R19_CALLBACK_RUNS")

    def test_proxy_outbound_remains_blocked_even_if_all_ticket_gates_ready(self):
        for ready, ticket in itertools.product((0, 1), repeat=2):
            self.assertEqual(verdict(example(route_ready=ready, ticket_valid=ticket)),
                             "BLOCK_IF_R19_CALLBACK_RUNS")

    def test_intended_redirected_client_is_only_a_candidate(self):
        for family in (4, 6):
            self.assertEqual(verdict(example("redirected_client", family=family)),
                             "PERMIT_CANDIDATE_NOT_NATIVE_PROOF")

    def test_unredirected_selected_direct_is_blocked_in_model(self):
        self.assertEqual(verdict(example("direct_client")), "BLOCK_IF_R19_CALLBACK_RUNS")

    def test_untracked_proxy_socket_not_an_admission_proof(self):
        # If original-id reverts to broker, the filter misses it, but the
        # mandated WFP record lineage is then not established.
        self.assertEqual(verdict(example(original_selected=0, records_set=0)),
                         "UNMATCHED_OUTSIDE_FILTER")

    def test_sibling_and_udp_outside_four_tcp_selected_filters(self):
        for case in (example(original_selected=0), example(tcp=0)):
            self.assertEqual(verdict(case), "UNMATCHED_OUTSIDE_FILTER")

    def test_honoring_policy_authorize_not_automatically_permitted(self):
        self.assertEqual(verdict(example("redirected_client", honoring=1)),
                         "BLOCK_IF_R19_CALLBACK_RUNS")

    def test_matrix_exact_size_and_family_symmetry(self):
        all_cases = list(cases())
        self.assertEqual(len(all_cases), 768)
        for i in range(384):
            self.assertEqual(verdict(all_cases[i]), verdict(all_cases[i + 384]))

    def test_countermodel_egress_exemption_mutation_is_detected(self):
        def mutated(c):
            if c["leg"] == "proxy_egress" and c["current_is_broker"]:
                return "PERMIT_CANDIDATE_NOT_NATIVE_PROOF"
            return verdict(c)
        self.assertNotEqual(verdict(example()), mutated(example()))

    def test_no_enforcement_attestation_from_synthetic_result(self):
        self.assertTrue(all("VERIFIED" not in verdict(c) and "GO" not in verdict(c)
                            for c in cases()))


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--matrix":
        sys.stdout.write(matrix())
    elif len(sys.argv) == 1:
        unittest.main()
    else:
        sys.exit("usage: python proxy_egress_negative.py [--matrix]")
