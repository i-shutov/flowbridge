#!/usr/bin/env python3
"""Offline source-composition regressions; no native or driver execution."""
import importlib.util
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import r156_callback_contract as c
ROOT = HERE.parent/'kernel-r19'
LEGACY = HERE.parent/'r155/r155_terminating_action_negative.py'

def load_legacy():
    raw = LEGACY.read_bytes()
    expected = '57ebe7287f4b0593ee8896fff1eb2b85cd5f4fd7'
    if c.blob(raw) != expected and c.blob(raw.replace(b'\r\n', b'\n')) != expected:
        raise RuntimeError('LEGACY_PIN_DRIFT')
    s = importlib.util.spec_from_file_location('legacy_r155', LEGACY)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m

class CompositionTests(unittest.TestCase):
    def test_exact_source_gate(self):
        self.assertEqual(len(c.source_gate(ROOT)), 4)
    def test_matrix(self):
        m=c.matrix();self.assertEqual(m['states'],720)
        self.assertEqual(m['reachable_self_returns'],48)
        self.assertEqual(m['sha256'],'54d4a483c38d0d0e4bff979a8881798a1dcf3eb0cde31adcd674c7ac7f52e78a')
    def test_independent_node(self):
        p=subprocess.run(['node',str(HERE/'r156_comprehensive_oracle.mjs')],capture_output=True,text=True,check=True,timeout=10)
        self.assertEqual(json.loads(p.stdout),c.matrix())
    def test_self_always_continue_with_write(self):
        for fam,prior,rights,stage in itertools.product((4,6),c.ACTIONS,(1,257,0xffffffff),('SELF','PREVIOUS_SELF')):
            r=c.evaluate(fam,prior,rights,stage)
            self.assertEqual(r['action'],'CONTINUE');self.assertTrue(r['query_reached']);self.assertEqual(r['rights'],rights)
    def test_no_write_cannot_reach_query(self):
        for fam,prior,rights,stage in itertools.product((4,6),c.ACTIONS,(0,256,0xfffffffe),('SELF','PREVIOUS_SELF','OTHER','NOT_REDIRECTED','RECORDS_ABSENT')):
            r=c.evaluate(fam,prior,rights,stage);self.assertFalse(r['query_reached'])
            self.assertTrue(r['path'].startswith('NO_WRITE_BEFORE_QUERY:'))
    def test_no_write_permit_veto(self):
        for rights in (0,256,0xfffffffe):
            r=c.evaluate(4,'PERMIT',rights,'SELF');self.assertEqual(r['action'],'BLOCK');self.assertEqual(r['rights'],rights)
    def test_no_write_nonpermit_preserved(self):
        for prior in ('BLOCK','CONTINUE','NONE'):
            r=c.evaluate(6,prior,256,'SELF');self.assertEqual(r['action'],prior);self.assertEqual(r['rights'],256)
    def test_unrelated_right_bits_survive_block(self):
        r=c.evaluate(4,'NONE',0xffffffff,'STOPPING')
        self.assertEqual(r['rights'],0xfffffffe);self.assertEqual(r['action'],'BLOCK')
    def test_null_output_has_no_writes(self):
        r=c.evaluate(4,'PERMIT',257,'NO_OUTPUT');self.assertEqual(r['action'],'PERMIT');self.assertFalse(r['action_is_final_for_modelled_path'])
    def test_failures_do_not_query(self):
        for stage in ('RUNDOWN_DENIED','STOPPING','UNCONFIGURED','NULL_INPUT','INVALID_APPID','MISSING_IDENTITY','NON_TCP'):
            r=c.evaluate(4,'NONE',257,stage);self.assertEqual(r['action'],'BLOCK');self.assertFalse(r['query_reached'])
    def test_foreign_appid_is_return_not_native_direct_proof(self):
        r=c.evaluate(4,'BLOCK',1,'FOREIGN_APPID');self.assertEqual(r['action'],'CONTINUE');self.assertFalse(r['release_accepted'])
    def test_other_redirect_queries_then_blocks(self):
        r=c.evaluate(6,'PERMIT',1,'OTHER');self.assertTrue(r['query_reached']);self.assertEqual(r['action'],'BLOCK')
    def test_modifying_path_does_not_claim_final_verdict(self):
        for stage in ('NOT_REDIRECTED','RECORDS_ABSENT'):
            r=c.evaluate(4,'NONE',1,stage);self.assertFalse(r['action_is_final_for_modelled_path'])
    def test_invalid_values_rejected_instead_of_coerced(self):
        for args in [(True,'NONE',1,'SELF'),(4,'NONE',True,'SELF'),(4,'NONE',1.0,'SELF'),(4,'NONE',-1,'SELF'),(4,'NONE',2**32,'SELF'),(4,'NONE',1,'AUTH'),(4,'bad',1,'SELF')]:
            with self.assertRaises(c.ContractError):c.evaluate(*args)
    def test_missing_sources_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):c.source_gate(Path(tmp))
    def test_each_source_tamper_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in c.PINS:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
            for name in c.PINS:
                p=root/name;original=p.read_bytes();p.write_bytes(original+b' ')
                with self.assertRaises(c.ContractError):c.source_gate(root)
                p.write_bytes(original)
    def test_crlf_normalization_recovers_only_exact_blobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in c.PINS:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes((ROOT/name).read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
            records=c.source_gate(root)
            self.assertEqual(len(records),4)
            self.assertTrue(all(r['crlf_normalized'] is True for r in records))
            self.assertEqual({r['path']:r['git_blob'] for r in records},c.PINS)
    def test_frozen_legacy_crlf_is_still_the_same_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'legacy.py'
            p.write_bytes(LEGACY.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))
            with patch(__name__+'.LEGACY',p):
                self.assertEqual(load_legacy().verdict('SELF','NONE',1,4),('SELF_RETURN_UNSET', 'UNSPECIFIED'))
    def test_bom_bare_cr_and_whitespace_are_not_normalized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in c.PINS:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((ROOT/name).read_bytes())
            target=root/'kernel/src/lib.rs';raw=target.read_bytes()
            for changed in (b'\xef\xbb\xbf'+raw,raw+b' ',raw.replace(b'\n',b'\r'),raw[:-1]):
                target.write_bytes(changed)
                with self.assertRaises(c.ContractError):c.source_gate(root)
    def test_shape_detects_missing_wrapper_even_without_pin(self):
        texts={n:(ROOT/n).read_text() for n in c.PINS}
        texts['kernel/src/lib.rs']=texts['kernel/src/lib.rs'].replace('(*out).actionType=k::FWP_ACTION_CONTINUE;','(*out).actionType=k::FWP_ACTION_NONE;')
        with self.assertRaises(c.ContractError):c.source_shape(texts)
    def test_shape_detects_late_wrapper_initialization(self):
        texts={n:(ROOT/n).read_text() for n in c.PINS}
        line='    if !out.is_null() && (*out).rights & k::FWPS_RIGHT_ACTION_WRITE!=0{(*out).actionType=k::FWP_ACTION_CONTINUE;}\n'
        s=texts['kernel/src/lib.rs'].replace(line,'')
        s=s.replace('    redirect::classify(values,meta,_context,_filter,out);','    redirect::classify(values,meta,_context,_filter,out);\n'+line)
        texts['kernel/src/lib.rs']=s
        with self.assertRaises(c.ContractError):c.source_shape(texts)
    def test_shape_detects_missing_prequery_right_check(self):
        texts={n:(ROOT/n).read_text() for n in c.PINS}
        texts['kernel/src/redirect.rs']=texts['kernel/src/redirect.rs'].replace('if incoming_write==0||','if ')
        with self.assertRaises(c.ContractError):c.source_shape(texts)
    def test_shape_detects_wrong_callback_registration(self):
        texts={n:(ROOT/n).read_text() for n in c.PINS}
        texts['kernel/src/lib.rs']=texts['kernel/src/lib.rs'].replace('if i<2{classify}else{auth_callback}','if i<2{auth_callback}else{classify}')
        with self.assertRaises(c.ContractError):c.source_shape(texts)
    def test_legacy_reproduction_is_not_acceptance(self):
        old=load_legacy();changed=unreachable=0
        for fam,state,action,write in itertools.product((4,6),old.STATES,old.ACTIONS,(0,1)):
            _,legacy=old.verdict(state,action,write,fam)
            now=c.evaluate(fam,action,write,state)
            changed+=int(legacy!=('UNSPECIFIED' if now['action']=='NONE' else now['action']))
            unreachable+=int(not now['query_reached'])
        self.assertEqual(changed,16);self.assertEqual(unreachable,16)
    def test_concurrent_model_still_skips_the_prequery_guard(self):
        path=HERE/'r156_callback_composition.py';raw=path.read_bytes()
        expected='d9e4798a7c734bafd4584302434373c3bd1e4066'
        self.assertIn(expected,(c.blob(raw),c.blob(raw.replace(b'\r\n',b'\n'))))
        spec=importlib.util.spec_from_file_location('concurrent_r156',path)
        other=importlib.util.module_from_spec(spec);spec.loader.exec_module(other)
        changed=unreachable=0
        for fam,state,prior in itertools.product((4,6),('SELF','PREVIOUS_SELF'),c.ACTIONS):
            previous=other.callback_return(fam,state,prior,0,'SELF_RETURN')
            actual=c.evaluate(fam,prior,0,state)
            changed+=int(previous[0]!=actual['action']);unreachable+=int(not actual['query_reached'])
        self.assertEqual(changed,4);self.assertEqual(unreachable,16)
    def test_all_rows_keep_native_and_release_false(self):
        for _,r,_ in c.matrix_rows():self.assertIs(r['native_wfp_executed'],False);self.assertIs(r['release_accepted'],False)
    def test_cli_source_pin_modes_agree(self):
        expected={**c.matrix(),'source_pins_checked':True}
        for flags in ([],['-O'],['-OO']):
            p=subprocess.run([sys.executable,*flags,'-B',str(HERE/'r156_callback_contract.py'),'--source-root',str(ROOT)],capture_output=True,text=True,check=True,timeout=10)
            self.assertEqual(json.loads(p.stdout),expected)
    def test_cli_requires_mode(self):
        p=subprocess.run([sys.executable,'-B',str(HERE/'r156_callback_contract.py')],capture_output=True,timeout=10)
        self.assertNotEqual(p.returncode,0)

if __name__=='__main__':unittest.main(verbosity=2)
