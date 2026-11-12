#!/usr/bin/env python3
"""Pure decision oracle. Never claims that 256 cases correspond to Windows events."""
import hashlib,json
REQUIRED=('MEM_IMAGE_at_EXE_base','mapped_name_stable','mapping_matches_process_native','mapping_matches_held_file_native','file_ID_stable','opaque_AppId_stable_across_names','process_Win32_name_stable')
def outcome(mask:int)->int:
    if type(mask) is not int or not 0<=mask<=255:raise ValueError('mask out of range')
    return 0 if all((mask>>i)&1 for i in range(len(REQUIRED))) else 3
def matrix()->bytes:return ''.join(f'{i:03d}:{outcome(i)}\n' for i in range(256)).encode('ascii')
def result()->dict:return {'states':256,'consistent':sum(outcome(i)==0 for i in range(256)),
    'sha256':hashlib.sha256(matrix()).hexdigest()}
if __name__=='__main__':print(json.dumps(result(),sort_keys=True))
