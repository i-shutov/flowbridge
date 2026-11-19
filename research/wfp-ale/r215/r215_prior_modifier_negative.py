#!/usr/bin/env python3
"""R215 conditional pre-ISSUE predecessor test. Never touches WFP/network."""
import argparse
import hashlib
import json
from pathlib import Path


def decide(family: int, predecessor: str, record: str, auth_destination: str) -> dict:
    # Model the R19 source ORDER, not kernel reachability. The scenario assumes
    # all unrelated gates (exact AppId, TCP, lease, PID/epoch, metadata) pass.
    original = f"{family}:original"
    current = f"{family}:modified" if predecessor == "remote" else original
    if record == "self":
        outcome = "continue_no_ticket"
    elif record == "other":
        outcome = "block_no_ticket"
    else:
        # R19 reads FWPS_CONNECT_REQUEST0.remoteAddressAndPort without examining
        # previousVersion; a prior modifier can change the value being ticketed.
        trusted_from = current
        auth_value = original if auth_destination == "initial" else current
        outcome = "local_attest_candidate" if trusted_from == auth_value else "auth_block"
    return {
        "family": family, "predecessor": predecessor, "record": record,
        "auth_destination": auth_destination, "outcome": outcome,
        "original_preserved": (current == original),
        "evidence_gap": (outcome == "local_attest_candidate" and current != original)
    }


def rows() -> list[dict]:
    return [decide(f,p,r,a) for f in (4,6)
            for p in ("none","remote","token")
            for r in ("absent","self","other")
            for a in ("initial","current")]


def guard(source: str) -> None:
    assert "let remote=slice::from_raw_parts((&request.remoteAddressAndPort" in source
    assert "r.book.issue(origin,dest,time)" in source
    assert "route.book.attest(identity,original_destination,now())" in source
    assert "FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE" in source
    assert "request.previousVersion" not in source
    assert "request.modifierFilterId" not in source


def main() -> None:
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path);args=ap.parse_args()
    if args.source:guard(args.source.read_text(encoding='utf-8'))
    rr=rows();assert len(rr)==36
    assert sum(x['evidence_gap'] for x in rr)==2  # IPv4/v6 remote predecessor, records absent, AUTH follows current
    for x in rr:
        if x['record']=='self':assert x['outcome']=='continue_no_ticket'
        if x['record']=='other':assert x['outcome']=='block_no_ticket'
        if x['predecessor']=='remote' and x['auth_destination']=='initial' and x['record']=='absent':assert x['outcome']=='auth_block'
    wire=''.join(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n' for x in rr)
    print(json.dumps({'cases':len(rr),'conditional_gap':2,'sha256':hashlib.sha256(wire.encode()).hexdigest(), 'source_guard':'PASS' if args.source else 'NOT_RUN'},sort_keys=True))

if __name__=='__main__':main()
