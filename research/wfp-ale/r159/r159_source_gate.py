#!/usr/bin/env python3
"""R159 source-only BFE-readback -> ARM binding gate; NO driver/Windows APIs."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
K=ROOT/"kernel-r19"
PIN={
    "policy_plan.rs":"0c3d0e88eb9d06f4030131d9533da2d629dbdab0",
    "broker_windows.rs":"329ef14b63e70226bfad7372b0014559213abd04",
    "broker.rs":"6163e84aea08ddde7e51a7fb94ccb6d68ae951fb",
    "policy_windows.rs":"acf60334320d970f58af3349ee75fbaa59826602",
}
def git_blob(content:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(content)).encode()+b"\0"+content).hexdigest()

def sources()->dict[str,str]:
    observed={}
    for name,pin in PIN.items():
        data=(K/name).read_bytes()
        if git_blob(data)!=pin: raise ValueError("changed source blob: "+name)
        observed[name]=data.decode("utf-8")
    return observed

def assert_shape(s):
    b=s["broker.rs"];w=s["broker_windows.rs"];p=s["policy_plan.rs"]
    if b.count("let policy=if activate_policy{")!=1 or b.count("device.arm(&selection,&plan,ports[0],ports[1])")!=1:
        raise ValueError("unbound or repeated activation")
    if not (b.index("let policy=if activate_policy{")<
            b.index("policy_windows::Installed::activate_admitted(&plan)")<
            b.index("device.arm(&selection,&plan,ports[0],ports[1])")<
            b.index("let heartbeat=")):
        raise ValueError("readback/ARM order bypassed")
    if "if !plan.arm_matches(image.wfp_appid(),[port4,port6]){return Err(fail());}" not in w:
        raise ValueError("Device::arm lacks typed reject path")
    if "self.appid.as_slice()==selected_appid && self.ports==ports" not in p:
        raise ValueError("byte/port binding absent")
    if "pub fn verify_plan_only" not in s["policy_windows.rs"] or "FWPM_SESSION_FLAG_DYNAMIC" not in s["policy_windows.rs"]:
        raise ValueError("policy source not pinned/dynamic boundary lost")
    if b.count("policy_windows::Installed::activate_admitted(&plan)")!=1:
        raise ValueError("multiple BFE installation paths")
    return True

def admitted(plan:bytes,selected:bytes,plan_ports:tuple[int,int],arm_ports:tuple[int,int])->bool:
    return plan==selected and plan_ports==arm_ports

class Checks(unittest.TestCase):
    def test_same_bytes_same_ports(self):
        self.assertTrue(admitted(b"A\0",b"A\0",(1091,1092),(1091,1092)))
    def test_different_targets(self):
        self.assertFalse(admitted(b"A\0",b"B\0",(1091,1092),(1091,1092)))
    def test_missing_terminator(self):
        self.assertFalse(admitted(b"A\0",b"A",(1091,1092),(1091,1092)))
    def test_swapped_ports(self):
        self.assertFalse(admitted(b"A\0",b"A\0",(1091,1092),(1092,1091)))
    def test_changed_one_port(self):
        self.assertFalse(admitted(b"A\0",b"A\0",(1091,1092),(1091,1093)))
    def test_empty_bytes_cannot_make_real_plan(self):
        # Callers must still invoke Plan::new for semantic validation.
        self.assertTrue(admitted(b"",b"",(1091,1092),(1091,1092)))
    def test_exact_source_blobs(self):
        self.assertEqual(set(sources()),set(PIN))
    def test_source_call_order(self):
        self.assertTrue(assert_shape(sources()))
    def test_old_order_rejected(self):
        s=sources();b=s["broker.rs"]
        s["broker.rs"]=b.replace("device.arm(&selection,&plan,ports[0],ports[1])",
                                 "device.arm(&selection,ports[0],ports[1])")
        with self.assertRaises(ValueError):assert_shape(s)
    def test_equality_guard_removed_rejected(self):
        s=sources();s["broker_windows.rs"]=s["broker_windows.rs"].replace(
            "if !plan.arm_matches(image.wfp_appid(),[port4,port6]){return Err(fail());}","")
        with self.assertRaises(ValueError):assert_shape(s)
    def test_native_evidence_never_inferred(self):
        result=result_json()
        for key in ("native_wfp_executed","kernel_origin_proof","no_direct_proof",
                    "release_accepted","bfe_loss_protected"):
            self.assertIs(result[key],False)

def result_json():
    return {"schema":1,"stage":"R159_SOURCE_ADMISSION_ONLY",
            "source_blobs":PIN,"native_wfp_executed":False,
            "kernel_origin_proof":False,"bfe_loss_protected":False,
            "no_direct_proof":False,"release_accepted":False}

if __name__=="__main__":
    if sys.argv[1:]==["--source-gate"]:
        assert_shape(sources())
        print(json.dumps(result_json(),sort_keys=True,indent=2))
    else:
        unittest.main(verbosity=2)
