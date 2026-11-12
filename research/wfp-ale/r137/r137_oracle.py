#!/usr/bin/env python3
"""Offline specification for a filename-only WFP AppId negative control.

This model is not a simulation of Windows API behavior. It only constrains
interpretation of hypothetical observations. 0 never means kernel-origin proof.
"""
import hashlib, json

def diagnostic(mask):
    if type(mask) is not int or not 0 <= mask <= 255:
        raise ValueError('invalid observation mask')
    if mask & 0x0f != 0x0f:
        return 3, 'NOT_STABLE_OR_NOT_CONFIRMED_ABSENT'
    if mask & 0x10 == 0:
        return 4, 'ABSENT_PATH_APPID_REJECTED_NOT_ORIGIN_PROOF'
    if mask & 0x20:
        return 0, 'ABSENT_PATH_APPID_ACCEPTED_NOT_ORIGIN_PROOF'
    return 3, 'AMBIGUOUS_APPID_EQUAL_TO_OWN_IMAGE'

def matrix():
    return ''.join(f'{m:03}:{diagnostic(m)[0]}\n' for m in range(256))

def result():
    cases = [diagnostic(m)[0] for m in range(256)]
    return {
        'states':256,'diagnostic_exit_counts':{str(k):cases.count(k) for k in (0,3,4)},
        'sha256':hashlib.sha256(matrix().encode('ascii')).hexdigest(),
    }

if __name__=='__main__':print(json.dumps(result(),sort_keys=True))
