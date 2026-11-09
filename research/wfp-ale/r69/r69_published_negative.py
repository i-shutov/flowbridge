#!/usr/bin/env python3
"""R69 source-pinned WFP-state counterexample, offline, not packet evidence."""
import hashlib
import json
import unittest

# Bit flags: original selected, current selected, TCP, records-present,
# records-nonnull, identity+lease valid, auth-callback, physical owner alive.
# States: NOT=0, SELF=1, OTHER=2, PREVIOUS_SELF=3, MAX=4.
AUTH_DOCUMENTED = {'PROCESS_ID', 'TRANSPORT_ENDPOINT_HANDLE'}
AUTH_REQUIRED = {'PROCESS_ID', 'TRANSPORT_ENDPOINT_HANDLE',
                 'LOCAL_REDIRECT_TARGET_PID', 'ORIGINAL_DESTINATION'}

def outcome(mask, state):
    orig, cur, tcp, present, nonnull, healthy, callback, alive = \
        (bool(mask & (1 << i)) for i in range(8))
    if not (cur and tcp): redirect = 0  # own BFE filter not selected
    elif present and not nonnull: redirect = 1  # no documented null-handle result
    elif present and state in (1,3): redirect = 2  # self -> CONTINUE, no new redirect
    elif present and state in (2,4): redirect = 3  # OTHER/unknown -> BLOCK requested
    elif not healthy: redirect = 4
    elif present: redirect = 5  # explicit NOT_REDIRECTED -> issue candidate
    else: redirect = 6  # record-bit ABSENT -> skipped query, issue candidate
    auth = 0 if not (orig and tcp) else (1 if not callback else 2)
    # No original-owner proof or packet verdict is inferred from any output.
    return redirect, auth, int(redirect == 6 and state in (1,2,3)), \
           int(redirect == 6 and not alive), int(redirect == 2 and not healthy)

def summary():
    counts = {'states':0,'redirect':[0]*7,'auth':[0]*3,
              'missing_records_nonclean_worlds':0,'dead_owner_unknown_issue':0,
              'self_continue_without_health':0,'no_native_packets':True,
              'auth_required_not_in_published_layer_table':sorted(AUTH_REQUIRED-AUTH_DOCUMENTED)}
    digest=hashlib.sha256()
    for family in (4,6):
        for state in range(5):
            for mask in range(256):
                result=outcome(mask,state)
                counts['states']+=1
                counts['redirect'][result[0]]+=1
                counts['auth'][result[1]]+=1
                for key,value in zip(('missing_records_nonclean_worlds',
                                      'dead_owner_unknown_issue','self_continue_without_health'),result[2:]):
                    counts[key]+=value
                digest.update((f'{family}|{state}|{mask}|'+','.join(map(str,result))+'\n').encode())
    counts['sha256']=digest.hexdigest()
    return counts

class Negative(unittest.TestCase):
    def test_record_missing_skips_query_even_if_hidden_other(self):
        # all bits except records_present, owner alive / no distinction required
        m=255 & ~(1<<3)
        self.assertEqual({outcome(m,s)[0] for s in range(5)}, {6})
    def test_known_four_states_and_max(self):
        self.assertEqual([outcome(255,s)[0] for s in range(5)],[5,2,3,2,3])
    def test_null_records_is_not_clean(self):
        self.assertEqual(outcome(255 & ~(1<<4),0)[0],1)
    def test_health_loss_does_not_prevent_self_continue(self):
        self.assertEqual(outcome(255 & ~(1<<5),1)[0],2)
    def test_original_selected_current_foreign_only_auth_scope(self):
        self.assertEqual(outcome(255 & ~(1<<1),0)[:2],(0,2))
    def test_current_selected_original_foreign_only_redirect(self):
        self.assertEqual(outcome(255 & ~(1<<0),0)[:2],(5,0))
    def test_missing_callback_is_unobserved(self):
        self.assertEqual(outcome(255 & ~(1<<6),0)[1],1)
    def test_two_fields_missing_from_auth_layer_inventory(self):
        self.assertEqual(sorted(AUTH_REQUIRED-AUTH_DOCUMENTED),
                         ['LOCAL_REDIRECT_TARGET_PID','ORIGINAL_DESTINATION'])
    def test_dead_owner_not_read_by_source(self):
        self.assertEqual(outcome(255,0)[0],outcome(255 & ~(1<<7),0)[0])
    def test_tcp_only(self):
        self.assertEqual(outcome(255 & ~(1<<2),0)[:2],(0,0))

if __name__ == '__main__':
    unittest.main(verbosity=2)
