"""R83 negative Winsock terminal state model; no kernel proof."""
import itertools,hashlib,unittest
def decision(rc,e,result,final,event,bytes_count,same):
    if rc==0: return "TERMINAL_OK_NO_PROOF"
    if rc!=-1:return "UNKNOWN_RETAIN"
    if e!=997:return "TERMINAL_ERROR_NO_PROOF"
    if not same:return "UNKNOWN_RETAIN"
    if result==1:return "TERMINAL_OK_NO_PROOF"
    if result==0 and final==995:return "TERMINAL_ERROR_NO_PROOF"
    return "UNKNOWN_RETAIN"
class Tests(unittest.TestCase):
    def test_pending_zero(self):self.assertEqual("UNKNOWN_RETAIN",decision(-1,997,0,996,0,0,1))
    def test_event_not_proof(self):self.assertEqual(decision(-1,997,0,996,0,0,1),decision(-1,997,0,996,1,42,1))
    def test_socket_mismatch(self):self.assertEqual("UNKNOWN_RETAIN",decision(-1,997,1,0,1,1,0))
    def test_aborted(self):self.assertEqual("TERMINAL_ERROR_NO_PROOF",decision(-1,997,0,995,1,1,1))
    def test_param_error_not_terminal(self):self.assertEqual("UNKNOWN_RETAIN",decision(-1,997,0,10022,1,1,1))
    def test_immediate_success(self):self.assertEqual("TERMINAL_OK_NO_PROOF",decision(0,0,0,0,0,0,1))
    def test_immediate_error(self):self.assertEqual("TERMINAL_ERROR_NO_PROOF",decision(-1,10057,1,0,0,0,1))
    def test_pending_success(self):self.assertEqual("TERMINAL_OK_NO_PROOF",decision(-1,997,1,0,0,0,1))
def matrix():
    h=hashlib.sha256();counts={};total=0
    for v in itertools.product((0,-1,17),(0,997,10057),(0,1),(0,996,995,10022),(0,1),(0,42),(0,1)):
        label=decision(*v)
        h.update(("|".join(map(str,v))+"|"+label+"\n").encode())
        counts[label]=counts.get(label,0)+1;total+=1
    return total,h.hexdigest(),dict(sorted(counts.items()))
if __name__=="__main__":
    unittest.main(exit=False)
    print("MATRIX:",matrix())
