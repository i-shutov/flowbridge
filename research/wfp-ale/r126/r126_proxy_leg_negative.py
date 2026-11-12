#!/usr/bin/env python3
"""R126: deterministic, source-derived *conditional* ALE policy/callback model.
No WFP calls, drivers, network, or OS mutation. Assumptions are declared in report.
"""
import hashlib
import json
import unittest

FIELD_NAMES = ("original_selected", "tcp", "remote_loopback", "redirect_flag",
               "target_broker", "original_destination", "process_selected",
               "endpoint_ticket_matches", "not_reauthorize", "current_broker",
               "ssh_ready", "ipv6")

def model(i):
    f = dict(zip(FIELD_NAMES, ((i >> bit) & 1 == 1 for bit in range(12))))
    # R19 policy_windows.rs: original-AppId and TCP filter conditions.
    invoked = f["original_selected"] and f["tcp"]
    # R19 redirect.rs::auth_check: simplified necessary conditions; all omitted
    # conditions (metadata type, destination exactness, time etc.) are ASSUMED valid.
    allowed = invoked and all(f[x] for x in (
        "remote_loopback", "redirect_flag", "target_broker", "original_destination",
        "process_selected", "endpoint_ticket_matches", "not_reauthorize", "ssh_ready"))
    return f, "NO_MATCH" if not invoked else "PERMIT_CANDIDATE" if allowed else "BLOCK_CANDIDATE"

def run():
    counts = {"NO_MATCH": 0, "PERMIT_CANDIDATE": 0, "BLOCK_CANDIDATE": 0}
    proxy = no_match = 0
    data = []
    for i in range(4096):
        f, result = model(i)
        counts[result] += 1
        # Proxy uplink: inherited original selected AppId, current AppId broker,
        # actual socket owner broker, physical SSH IP remote nonloopback.
        if f["original_selected"] and f["tcp"] and f["current_broker"] \
                and not f["process_selected"] and not f["remote_loopback"]:
            proxy += 1
            assert result == "BLOCK_CANDIDATE"
        if not f["original_selected"] and f["tcp"]:
            no_match += 1
            assert result == "NO_MATCH"
        data.append(f"{i:04d}|{result}\n")
    return {"cases": 4096, "counts": counts, "proxy_leg_must_block_in_model": proxy,
            "unselected_original_no_filter": no_match,
            "matrix_sha256": hashlib.sha256(''.join(data).encode('ascii')).hexdigest()}

class Check(unittest.TestCase):
    def test_full_matrix(self):
        r = run()
        self.assertEqual(sum(r["counts"].values()), 4096)
        self.assertEqual(r["counts"]["PERMIT_CANDIDATE"], 4)
    def test_proxy_conditional_block_both_families(self):
        for ipv6 in [False, True]:
            bits = {"original_selected":1,"tcp":1,"remote_loopback":0,
                    "redirect_flag":0,"target_broker":0,"original_destination":0,
                    "process_selected":0,"endpoint_ticket_matches":0,
                    "not_reauthorize":1,"current_broker":1,"ssh_ready":1,"ipv6":int(ipv6)}
            i=sum(int(bits[k]) << n for n,k in enumerate(FIELD_NAMES))
            self.assertEqual(model(i)[1], "BLOCK_CANDIDATE")
    def test_current_app_is_not_filter_condition(self):
        for i in range(4096):
            if not (i & (1<<9)):
                self.assertEqual(model(i)[1], model(i | (1<<9))[1])
    def test_reauth_never_admitted(self):
        for i in range(4096):
            if not (i & (1<<8)):
                self.assertNotEqual(model(i)[1], "PERMIT_CANDIDATE")
    def test_external_destination_never_admitted(self):
        for i in range(4096):
            if not (i & (1<<2)):
                self.assertNotEqual(model(i)[1], "PERMIT_CANDIDATE")
    def test_unselected_ssh_no_match(self):
        for i in range(4096):
            if not (i & 1):
                self.assertEqual(model(i)[1], "NO_MATCH")

if __name__ == "__main__":
    unittest.main(exit=False, verbosity=2)
    print('R126_MATRIX=' + json.dumps(run(), sort_keys=True, separators=(',', ':')))
