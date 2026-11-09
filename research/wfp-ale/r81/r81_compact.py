"""R81 finite negative model, no network, filters, driver or FFI."""
import hashlib,itertools,json,unittest

def decide(ip,proto,alive,close,barrier,future,pending,bfe,ssh):
    scope='TCP_CANDIDATE' if proto==6 else 'NOT_MATCHED_BY_R19'
    session=('DYNAMIC_SESSION_ENDED' if not alive or close=='ok' else
             'CLOSE_OUTCOME_UNKNOWN' if close=='error' else
             'BFE_UNVERIFIED' if not bfe else 'SESSION_OPEN_MODELED')
    return (scope,session,int(pending==0),int(bool(alive and close=='error')),
            int(bool(future and not barrier and (proto!=6 or session!='SESSION_OPEN_MODELED'))))

def matrix():
    rows=itertools.product([4,6],[6,17,1,58],[0,1],['none','ok','error'],[0,1],[0,1],[0,1,32],[0,1],[0,1])
    digest=hashlib.sha256();counts={};n=0
    for row in rows:
        out=decide(*row);n+=1
        digest.update(('|'.join(map(str,row+out))+'\n').encode())
        for key in out[:2]:counts[key]=counts.get(key,0)+1
        for key,val in zip(['CLOSE_REACHABLE','LOST_HANDLE','UNGUARDED_CASE'],out[2:]):
            if val:counts[key]=counts.get(key,0)+1
    return dict(total=n,sha256=digest.hexdigest(),counts=dict(sorted(counts.items())))

class ContractTests(unittest.TestCase):
    def test_tcp_and_udp_families(self):
        for ip in (4,6):
            assert decide(ip,6,1,'none',0,1,0,1,1)[0]=='TCP_CANDIDATE'
            assert decide(ip,17,1,'none',0,1,0,1,1)[0]=='NOT_MATCHED_BY_R19'
    def test_close_error_is_unknown_and_loses_handle(self):
        assert decide(4,6,1,'error',0,1,0,1,1)[1:4]==('CLOSE_OUTCOME_UNKNOWN',1,1)
    def test_owner_death_and_close_success_remove_dynamic_session(self):
        assert decide(4,6,0,'none',0,1,0,1,1)[1]=='DYNAMIC_SESSION_ENDED'
        assert decide(4,6,1,'ok',0,1,0,1,1)[1]=='DYNAMIC_SESSION_ENDED'
    def test_worker_pending_cannot_be_reaped_by_timeout(self):
        assert decide(4,6,1,'none',0,1,32,1,1)[2]==0
    def test_ssh_health_is_not_wfp_attestation(self):
        assert decide(4,6,1,'error',0,1,0,1,0)==decide(4,6,1,'error',0,1,0,1,1)
    def test_counterexample_hypothetical_barrier(self):
        assert decide(6,17,1,'none',0,1,0,1,1)[-1]==1
        assert decide(6,17,1,'none',1,1,0,1,1)[-1]==0
    def test_exhaustive_matrix(self):
        m=matrix();assert m['total']==2304 and m['counts']['UNGUARDED_CASE']>0

if __name__=='__main__':
    import sys
    if '--matrix' in sys.argv:print(json.dumps(matrix(),sort_keys=True))
    else:unittest.main(verbosity=2)
