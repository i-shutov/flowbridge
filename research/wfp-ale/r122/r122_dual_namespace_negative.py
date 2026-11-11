#!/usr/bin/env python3
"""Offline source-projection oracle for independently scoped network namespaces.
No sockets, WFP access, drivers, process introspection, or network operations.
"""
from itertools import product, combinations
from collections import defaultdict
from hashlib import sha256
import json
import unittest

# Distinct Windows source compartments can share addresses and ports. The broker
# has its own *unobserved* physical socket routing context: never assert it is 1.
DESTINATIONS = ((4, "10.55.0.7"), (6, "fd00:dead::7"))
PORTS = (443, 8443)
COMPARTMENTS = (1, 7, 42)
EPOCHS = (100, 101)
# Health/protocol failure is a local candidate denial, not a global no-DIRECT.

def project(family, address, port, origin_compartment, epoch, healthy, protocol):
    if not healthy or protocol != 6:
        return None
    # R19 outbound socket: socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) for the SSH
    # server. No source-compartment argument is passed into the socket request.
    # B is a symbolic, *unmeasured* OS-selected routing context, not a value.
    # The SSH payload contains numeric destination and port but no compartment.
    return ("BROKER_SOCKET_ROUTING_CONTEXT_UNKNOWN", family, address, port)


def hypothetical_remote_tag(family, address, port, compartment, epoch, healthy, protocol):
    value = project(family, address, port, compartment, epoch, healthy, protocol)
    if value is None:
        return None
    return value + (compartment,)


def single_compartment_gate(family, address, port, compartment, epoch, healthy, protocol):
    if compartment != 7:
        return None
    return project(family, address, port, compartment, epoch, healthy, protocol)


def measure():
    lines = []
    by_projection = defaultdict(list)
    candidate = gated = 0
    for (fam, addr), port, compartment, epoch, healthy, protocol in product(
        DESTINATIONS, PORTS, COMPARTMENTS, EPOCHS, (0, 1), (6, 17)
    ):
        row = (fam, addr, port, compartment, epoch, healthy, protocol)
        p = project(*row)
        g = single_compartment_gate(*row)
        candidate += p is not None
        gated += g is not None
        if p is not None:
            by_projection[p].append((compartment, epoch))
        lines.append("|".join(map(str, (*row, int(p is not None), int(g is not None)))))
    pairs = sum(
        x[0] != y[0]
        for group in by_projection.values()
        for x, y in combinations(group, 2)
    )
    same_epoch_pairs = sum(
        x[0] != y[0] and x[1] == y[1]
        for group in by_projection.values()
        for x, y in combinations(group, 2)
    )
    return {
        "cases": len(lines),
        "source_projection_candidates": candidate,
        "explicit_scope_candidates": gated,
        "cross_compartment_indistinguishable_pairs": pairs,
        "same_epoch_indistinguishable_pairs": same_epoch_pairs,
        "matrix_sha256": sha256(("\n".join(lines) + "\n").encode()).hexdigest(),
        "windows_egress_routing_verified": False,
        "wfp_kernel_causality_verified": False,
        "global_no_direct_verified": False,
    }


class DualNamespaceTests(unittest.TestCase):
    def test_two_origins_have_one_explicit_output_projection(self):
        a = project(4, "10.55.0.7", 443, 1, 100, 1, 6)
        b = project(4, "10.55.0.7", 443, 42, 100, 1, 6)
        self.assertEqual(a, b)

    def test_remote_tag_alone_is_not_physical_socket_route_witness(self):
        a = hypothetical_remote_tag(6, "fd00:dead::7", 443, 1, 100, 1, 6)
        b = hypothetical_remote_tag(6, "fd00:dead::7", 443, 42, 100, 1, 6)
        self.assertNotEqual(a, b)
        self.assertEqual(a[:4], b[:4])  # unchanged symbolic broker socket

    def test_explicit_scope_gate_is_not_evidence_of_inherited_routing(self):
        self.assertIsNone(single_compartment_gate(4, "10.55.0.7", 443, 1, 100, 1, 6))
        self.assertIsNotNone(single_compartment_gate(4, "10.55.0.7", 443, 7, 100, 1, 6))

    def test_udp_or_ssh_loss_says_nothing_about_unobserved_direct_path(self):
        for health, protocol in ((0, 6), (1, 17), (0, 17)):
            self.assertIsNone(project(4, "10.55.0.7", 443, 1, 100, health, protocol))

    def test_matrix(self):
        m = measure()
        self.assertEqual((m["cases"], m["source_projection_candidates"], m["explicit_scope_candidates"]), (96, 24, 8))
        self.assertEqual(m["cross_compartment_indistinguishable_pairs"], 48)
        self.assertEqual(m["same_epoch_indistinguishable_pairs"], 24)


if __name__ == "__main__":
    r = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DualNamespaceTests))
    if not r.wasSuccessful():
        raise SystemExit(1)
    print("R122_MATRIX " + json.dumps(measure(), sort_keys=True))
