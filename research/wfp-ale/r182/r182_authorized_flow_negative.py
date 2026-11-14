"""R182 clean-room, dependency-free offline model. Not Windows/WFP instrumentation.

Generates a deterministic predicate matrix for post-CLAIM ALE reauthorization.
A private, kernel-authenticated per-flow binding is an ASSUMPTION, not a WFP API claim.
"""
from __future__ import annotations
import hashlib
import itertools
import json
from dataclasses import dataclass, replace

FAMILIES = (4, 6)
PHASES = ("initial", "honor", "reauth")
CAUSES = ("policy", "interface", "ipsec", "classify_completion")
DIRECTIONS = ("out", "in")
TOKENS = ("trusted", "missing", "forged", "stale")
METADATA = ("full", "fwp_empty")
WORLDS = (
    "selected", "sibling_direct", "proxy_ssh", "pid_reused",
    "endpoint_reused", "tuple_reused", "foreign_compartment", "owner_dead",
    "bfe_lost", "ssh_lost", "revoked", "witness_unacked",
    "claim_absent", "not_established", "udp_dns",
)

@dataclass(frozen=True)
class Certificate:
    transaction: str = "tx-kernel-1"
    flow: str = "flow-kernel-1"
    owner_pid: int = 41
    creation_epoch: int = 101
    exe_id: str = "canonical-exe-A"
    endpoint: int = 77
    generation: int = 9
    compartment: int = 3
    tuple_id: str = "fixed-five-tuple"
    family: int = 4
    protocol: str = "tcp"
    session_epoch: int = 5
    bfe_epoch: int = 7
    ssh_epoch: int = 11
    original_appid: str = "selected"
    witness_ack: bool = True
    claimed: bool = True
    established: bool = True
    owner_alive: bool = True
    revoked: bool = False

@dataclass(frozen=True)
class Observation:
    phase: str
    cause: str
    direction: str
    metadata: str
    token_kind: str
    family: int
    presented_flow: str
    kernel_join_attested: bool
    original_appid: str
    tuple_id: str
    owner_pid: int
    creation_epoch: int
    exe_id: str
    endpoint: int
    generation: int
    compartment: int
    protocol: str
    session_epoch: int
    bfe_epoch: int
    ssh_epoch: int


def world_pair(family: int, world: str, phase: str, cause: str,
               direction: str, token: str, metadata: str) -> tuple[Certificate, Observation]:
    c = replace(Certificate(), family=family)
    o = Observation(phase, cause, direction, metadata, token, family,
                    c.flow if token in ("trusted", "forged") else
                    ("" if token == "missing" else "flow-old"),
                    token == "trusted", c.original_appid, c.tuple_id,
                    c.owner_pid, c.creation_epoch, c.exe_id, c.endpoint,
                    c.generation, c.compartment, c.protocol,
                    c.session_epoch, c.bfe_epoch, c.ssh_epoch)
    if world == "sibling_direct":
        o = replace(o, original_appid="sibling", owner_pid=42, exe_id="exe-B")
    elif world == "proxy_ssh":
        o = replace(o, original_appid="selected", owner_pid=99, exe_id="broker-exe")
    elif world == "pid_reused":
        o = replace(o, creation_epoch=202, exe_id="new-exe")
    elif world == "endpoint_reused":
        o = replace(o, generation=c.generation + 1)
    elif world == "tuple_reused":
        o = replace(o, endpoint=c.endpoint + 1, generation=c.generation + 1)
    elif world == "foreign_compartment":
        o = replace(o, compartment=c.compartment + 1)
    elif world == "owner_dead":
        c = replace(c, owner_alive=False)
    elif world == "bfe_lost":
        o = replace(o, bfe_epoch=c.bfe_epoch+1)
    elif world == "ssh_lost":
        o = replace(o, ssh_epoch=c.ssh_epoch+1)
    elif world == "revoked":
        c = replace(c, revoked=True)
    elif world == "witness_unacked":
        c = replace(c, witness_ack=False)
    elif world == "claim_absent":
        c = replace(c, claimed=False)
    elif world == "not_established":
        c = replace(c, established=False)
    elif world == "udp_dns":
        o = replace(o, protocol="udp")
    else:
        assert world == "selected"
    return c, o


def strict_authorize(c: Certificate, o: Observation) -> bool:
    # Every bit of the claimed trustworthy join is a premise supplied by the model.
    if o.phase != "reauth" or o.cause not in CAUSES:
        return False
    if not o.kernel_join_attested or o.presented_flow != c.flow:
        return False
    if not (c.witness_ack and c.claimed and c.established and c.owner_alive):
        return False
    if c.revoked or c.protocol != "tcp" or o.protocol != "tcp":
        return False
    if o.original_appid != c.original_appid or o.family != c.family:
        return False
    if (o.owner_pid, o.creation_epoch, o.exe_id) != (c.owner_pid, c.creation_epoch, c.exe_id):
        return False
    if (o.endpoint, o.generation, o.compartment) != (c.endpoint, c.generation, c.compartment):
        return False
    if (o.session_epoch, o.bfe_epoch, o.ssh_epoch) != (c.session_epoch, c.bfe_epoch, c.ssh_epoch):
        return False
    if o.tuple_id != c.tuple_id:
        return False
    return True


def unsafe_tuple_authorize(c: Certificate, o: Observation) -> bool:
    # The deliberately broken baseline ignores owner epoch, endpoint epoch,
    # kernel join, ACK/CLAIM, compartment, liveness, revocation, and BFE/SSH epoch.
    return (o.phase == "reauth" and o.original_appid == c.original_appid
            and o.family == c.family and o.tuple_id == c.tuple_id)


def matrix():
    for family, phase, cause, direction, token, metadata, world in itertools.product(
        FAMILIES, PHASES, CAUSES, DIRECTIONS, TOKENS, METADATA, WORLDS
    ):
        c, o = world_pair(family, world, phase, cause, direction, token, metadata)
        strict = strict_authorize(c, o)
        unsafe = unsafe_tuple_authorize(c, o)
        yield dict(family=family, phase=phase, cause=cause, direction=direction,
                   token=token, metadata=metadata, world=world,
                   strict=int(strict), unsafe=int(unsafe), false_allow=int(unsafe and not strict))


def canonical(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    for row in matrix():
        print(canonical(row))
