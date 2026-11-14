"""R181 independent, no-driver model of R19 AUTH reauthorization lifetime.

This models only the source branches cited in R181_REAUTH_LIFETIME_NO_GO.md.
No native WFP behavior is inferred from matrix cases.
"""
import itertools
import json

FAMILIES = (4, 6)
PHASES = ("issued", "attested", "claimed")
FLOWS = ("selected_redirect", "sibling_direct", "proxy_ssh", "endpoint_aba", "pid_aba")
HEALTH = ("up", "lost")


def one(family, phase, flow, health):
    # R19 auth_check explicitly denies IS_REAUTHORIZE, irrespective of all
    # later checks. We model only calls that actually reach the AUTH rule.
    source = "BLOCK_REAUTH"
    slot_live = phase != "claimed"
    auth_seen = phase != "issued"
    valid_identity = flow == "selected_redirect" and health == "up"
    # Hypothetical single-line change: remove reauthorization flag guard,
    # leave the existing Book::attest one-shot code unchanged.
    remove_bit_only = "ATTEST_CANDIDATE" if (slot_live and not auth_seen and valid_identity) else "DENY"
    # Unsafe bypass proposal: admit selected ORIGINAL_APP_ID and loopback port
    # without demanding a kernel-owned matching transaction/flow authority.
    # These are synthetic inputs, not an assertion that WFP emits this tuple.
    is_loopback = flow != "proxy_ssh"
    naive_app_loopback = "PERMIT" if is_loopback else "BLOCK"
    return dict(family=family, phase=phase, flow=flow, health=health,
                source=source, remove_bit_only=remove_bit_only,
                naive_app_loopback=naive_app_loopback)


def rows():
    for args in itertools.product(FAMILIES, PHASES, FLOWS, HEALTH):
        yield one(*args)


if __name__ == "__main__":
    for row in rows():
        print(json.dumps(row, separators=(",", ":"), ensure_ascii=True))
