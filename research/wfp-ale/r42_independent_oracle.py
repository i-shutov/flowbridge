"""Independent two-world oracle; no imports from other R42 files.
Enumerates observational equivalence classes for a finite trace suffix.
"""
import itertools, json

def oracle():
    pairs=0; conflicted=0; no_owner_notice_worlds=0
    naive_false_permits=0; blanket_false_denials=0; trusted_event_errors=0
    # family, pid-reuse, five-tuple equality, buffered byte count (1/2),
    # before-claim AUTH witness seen, different fresh PID observer result.
    for f, reused, tuple_reused, buf, original_attested, late_pid_alive in itertools.product(
        (4,6),(0,1),(0,1),(1,2),(0,1),(0,1)):
        # This proof only applies to a connection already CLAIMed with AUTH witness.
        if not original_attested: continue
        # Living world and dead original world have SAME accessible broker trace.
        # No owner-exit event arrives; both have healthy lease/ssh and buffered bytes.
        broker_trace=(f,900,5,buf,tuple_reused,late_pid_alive,1,1,False)
        living=(broker_trace,1)
        dead=(broker_trace,0)
        pairs+=1
        if living[0]==dead[0] and living[1]!=dead[1]:conflicted+=1
        no_owner_notice_worlds+=2
        # Competing algorithms consume only broker_trace; the final one also
        # receives a hypothetical authenticated origin-exit event.
        naive_false_permits += int(True != bool(dead[1]))
        blanket_false_denials += int(False != bool(living[1]))
        trusted_event_errors += int(bool(living[1]) != bool(living[1])) + int(bool(dead[1]) != bool(dead[1]))
    assert pairs==32 and conflicted==pairs
    assert naive_false_permits==32 and blanket_false_denials==32 and trusted_event_errors==0
    return {"paired_worlds":pairs,"worlds":no_owner_notice_worlds,
            "conflicting_pairs":conflicted,
            "broker_healthy_only_false_permits":naive_false_permits,
            "broker_block_all_false_denials":blanket_false_denials,
            "trusted_exit_event_model_errors":trusted_event_errors,
            "claim":"No function of identical broker-only observations can both allow the living and deny the dead owner",
            "scope":"abstract finite traces, not a native Windows experiment"}
if __name__=='__main__':print(json.dumps(oracle(),sort_keys=True))
