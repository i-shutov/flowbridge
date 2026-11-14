"""R183: exercise exact R182 recovery implementation with fsync + child-process crash.

Research user-mode only: no sockets, drivers, filtering APIs or system configuration.
"""
from __future__ import annotations
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "r182"))
from r182_crash_journal import OLD_SESSION, NEW_SESSION, RECORDS, encoded, recover

KINDS = ("grant", "ack", "claim")
ORDERS = tuple(itertools.permutations(KINDS))
FAMILIES = ("v4", "v6")


def frame_bytes(family: str, order: tuple[str, ...]) -> bytes:
    records = []
    for event in order:
        record = dict(RECORDS[event])
        if event == "grant":
            record["tuple"] = family + "-fixed-five-tuple"
        records.append(encoded(record))
    return b"".join(records)


def safe_replay(order: tuple[str, ...], session: str) -> bool:
    # Candidate invariant for strictly this three-event example: durable GRANT
    # then durable ACK then CLAIM. This is not kernel-origin proof.
    return session == OLD_SESSION and order == KINDS


def row(family: str, order: tuple[str, ...], path: Path) -> dict:
    actual = path.read_bytes()
    assert actual == frame_bytes(family, order)
    out = recover(path, OLD_SESSION)
    assert out["valid"], out
    assert recover(path, NEW_SESSION)["strict"] is False
    return {"family": family, "legacy": out["strict"],
            "order": ">".join(order), "safe": safe_replay(order, OLD_SESSION)}


def worker(path: Path, family: str, order: tuple[str, ...]) -> None:
    # No cleanup: true child process exit after individual fsync barriers.
    with path.open("wb", buffering=0) as file:
        for event in order:
            rec = dict(RECORDS[event])
            if event == "grant":
                rec["tuple"] = family + "-fixed-five-tuple"
            file.write(encoded(rec))
            file.flush()
            os.fsync(file.fileno())
        os._exit(62)


def generate(folder: Path) -> list[dict]:
    folder.mkdir(parents=True, exist_ok=True)
    result = []
    for family in FAMILIES:
        for idx, order in enumerate(ORDERS):
            path = folder / (family + "_" + str(idx) + ".bin")
            proc = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                   "worker", str(path), family, *order],
                                  capture_output=True, check=False)
            assert proc.returncode == 62 and path.is_file(), (family, order, proc.stderr)
            result.append(row(family, order, path))
    assert len(result) == 12
    assert sum(r["legacy"] for r in result) == 12
    assert sum(r["safe"] for r in result) == 2
    assert sum(r["legacy"] and not r["safe"] for r in result) == 10
    return result


def canonical(r: dict) -> str:
    return json.dumps(r, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "worker":
        worker(Path(sys.argv[2]), sys.argv[3], tuple(sys.argv[4:]))
    elif len(sys.argv) == 3 and sys.argv[1] == "generate":
        result = generate(Path(sys.argv[2]))
        for r in result:
            print(canonical(r))
    elif len(sys.argv) == 2 and sys.argv[1] == "self-test":
        with tempfile.TemporaryDirectory(prefix="fb-r183-") as folder:
            result = generate(Path(folder))
            digest = hashlib.sha256(("\n".join(map(canonical, result)) + "\n").encode()).hexdigest()
            print("12 PASS; 10 counterexamples; canonical SHA256", digest)
    else:
        raise SystemExit("use: self-test | generate OUTPUT_DIR")
