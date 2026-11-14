"""R180 source-pinned AUTH phase counterexamples; synthetic data, no Windows/WFP calls."""
from __future__ import annotations
import itertools, json
from collections import Counter

REDIRECTED=0x00100000
PROXY=0x00200000
HONOR=0x02000000
REAUTH=0x00000004

# We deliberately do NOT infer classification from stage labels; the bits and
# source metadata guards decide. Stage labels merely constrain the endpoint.
STAGES=('policy_honor_original','redirected_loopback','record_tagged_ssh','sibling_direct')

def source_result(stage,flags,original,owner,metadata,ticket,correct_port,family):
    if original!='selected': return 'OUTSIDE_FILTER'
    # model of redirect.rs::auth_check mandatory fields/flags/endpoint/owner + Book::attest.
    actual_loopback = stage=='redirected_loopback'
    if not metadata or not (flags & REDIRECTED) or (flags & (HONOR|REAUTH)):
        return 'SOURCE_BLOCK_REQUEST'
    if not actual_loopback or not correct_port or owner!='selected' or not ticket:
        return 'SOURCE_BLOCK_REQUEST'
    return 'ATTEST_CANDIDATE_ONLY'

def rows():
    for family,stage,flagged,original,owner,metadata,ticket,correct_port in itertools.product(
        (4,6), STAGES, range(8), ('selected','broker'), ('selected','broker'),
        (False,True), (False,True), (False,True)):
        flags=(REDIRECTED if flagged&1 else 0)|(PROXY if flagged&2 else 0)|(HONOR if flagged&4 else 0)
        result=source_result(stage,flags,original,owner,metadata,ticket,correct_port,family)
        yield dict(family=family,stage=stage,flags=flags,original=original,owner=owner,
                   metadata=metadata,ticket=ticket,correct_port=correct_port,result=result)

def generate():
    return [json.dumps(x,sort_keys=True,separators=(',',':')) for x in rows()]

if __name__=='__main__':
    mat=list(rows());count=Counter(x['result'] for x in mat)
    assert len(mat)==2048 and sum(count.values())==2048,count
    # A Microsoft-described HONOR-only preauthorization phase must not be
    # treated as having the effective redirected loopback endpoint.
    pre=[x for x in mat if x['stage']=='policy_honor_original' and (x['flags'] & HONOR)
         and x['original']=='selected']
    assert len(pre)==128 and all(x['result']=='SOURCE_BLOCK_REQUEST' for x in pre)
    # Conditional originalAppId scope collides with physical SSH even if tagged.
    phys=[x for x in mat if x['stage']=='record_tagged_ssh' and (x['flags'] & PROXY)
          and x['original']=='selected']
    assert len(phys)==128 and all(x['result']=='SOURCE_BLOCK_REQUEST' for x in phys)
    # No selected-original sibling direct can be 'attested' by endpoint/ledger.
    sib=[x for x in mat if x['stage']=='sibling_direct' and x['original']=='selected']
    assert len(sib)==256 and all(x['result']=='SOURCE_BLOCK_REQUEST' for x in sib)
    # Positive source-level test candidates are *only* redirected-loopback.
    pos=[x for x in mat if x['result']=='ATTEST_CANDIDATE_ONLY']
    assert pos and all(x['stage']=='redirected_loopback' for x in pos)
    # Flag PROXY is NOT checked by existing R19 auth_check, so even the
    # synthetic R+P case can reach candidate status if all other guards hold.
    assert any(x['flags']&PROXY for x in pos)
    for line in generate(): print(line)
