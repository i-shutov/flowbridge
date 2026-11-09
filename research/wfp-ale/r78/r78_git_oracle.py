"""R78 model, not a native WFP test; stdlib only."""
import hashlib
import json
import unittest

def classify(cap, bogus, completed, real):
    # WorkerPool::spawn counts active handles BEFORE receive() validates WFP.
    active = (["relay"] if real else []) + ["unverified"] * min(bogus, cap-real)
    for i in range(min(completed, len(active)-real)):
        active[real+i] = "finished"
    active = [x for x in active if x != "finished"]  # spawn() polls
    dropped_bogus = max(0, bogus-(cap-real))
    denied = len(active) == cap
    return ("DROP" if denied else "SCHEDULE"), dropped_bogus+int(denied)

def audit():
    digest = hashlib.sha256()
    counts = {"DROP":0, "SCHEDULE":0}
    for family in (4,6):
        for cap in (1,2,4,32):
            for bogus in range(cap+2):
                for completed in range(cap+2):
                    for real in (0,1):
                        verdict, n = classify(cap,bogus,completed,real)
                        counts[verdict] += 1
                        digest.update(f"{family},{cap},{bogus},{completed},{real}|{verdict}|{n}\n".encode())
    return dict(cases=sum(counts.values()), outcomes=counts, sha256=digest.hexdigest())

class Tests(unittest.TestCase):
    def test_cross_family_starvation(self):
        self.assertEqual(classify(32,32,0,0)[0], "DROP")
    def test_completion_recovers_slot(self):
        self.assertEqual(classify(32,32,1,0)[0], "SCHEDULE")
    def test_live_relay_plus_unverified(self):
        self.assertEqual(classify(32,31,0,1)[0], "DROP")
    def test_repeated_unverified_does_not_accumulate(self):
        self.assertEqual(classify(32,32,32,0)[0], "SCHEDULE")

if __name__ == "__main__":
    import sys
    if "--oracle" in sys.argv: print(json.dumps(audit(),sort_keys=True))
    else: unittest.main()
