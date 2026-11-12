#!/usr/bin/env python3
"""Adversarial offline acceptance of R143. No WFP/driver/network operations."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'r143_policy_compiler.py'
NODE = HERE / 'r143_independent.mjs'
spec = importlib.util.spec_from_file_location('r143', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class CompilationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ref = m.reference()
        cls.compiled = m.compile_design(cls.ref, cls.ref)
    def bad_input(self, path, value):
        d=copy.deepcopy(self.ref)
        obj=d
        for k in path[:-1]: obj=obj[k]
        obj[path[-1]]=value
        with self.assertRaises(m.GateError): m.validate_input(d, self.ref)
    def bad_blueprint(self, path, value):
        d=copy.deepcopy(self.compiled)
        obj=d
        for key in path[:-1]: obj=obj[key]
        obj[path[-1]]=value
        d['blueprint_sha256']=m.digest({k:v for k,v in d.items() if k!='blueprint_sha256'})
        with self.assertRaises(m.GateError):m.validate_blueprint(d)
    def test_source_reference_sha(self):
        self.assertEqual(hashlib.sha256(m.R141.read_bytes()).hexdigest(),m.R141_SHA256)
    def test_reference_is_json_v1_and_design(self):
        self.assertEqual(self.ref['kind'],m.INPUT_KIND)
        self.assertIs(self.ref['apply_permitted'],False)
    def test_identical_input_compiles(self):
        self.assertEqual(m.compile_from_bytes(m.R141.read_bytes()),self.compiled)
    def test_default_equals_cli_output(self):
        raw=subprocess.check_output([sys.executable,'-B',str(SOURCE)])
        self.assertEqual(raw,m.canonical_bytes(self.compiled))
    def test_compiler_determinism(self):
        self.assertEqual(m.compile_from_bytes(),m.compile_from_bytes())
        self.assertEqual(m.digest(self.compiled),m.digest(m.compile_from_bytes()))
    def test_compiled_fingerprint(self):
        t=self.compiled
        self.assertEqual(t['blueprint_sha256'],m.digest({k:v for k,v in t.items() if k!='blueprint_sha256'}))
    def test_no_installer_guids_appid(self):
        t=self.compiled
        for k in ('apply_permitted','installer_present','real_guids_present','real_selected_appid_present','native_wfp_executed','release_accepted','no_direct_proved'):
            self.assertIs(t[k],False)
        self.assertNotIn('FwpmFilterAdd',m.canonical_bytes(t).decode())
    def test_provisioning_dependencies_topological(self):
        symbols=set()
        for ob in self.compiled['graph']:
            self.assertTrue(all(d in symbols for d in ob['depends_on']))
            symbols.add(ob['symbol'])
    def test_rollback_reverses_dependency_order(self):
        self.assertEqual(self.compiled['rollback_design_order'],list(reversed(self.compiled['provisioning_design_order'])))
        self.assertIs(self.compiled['rollback_executable'],False)
    def test_four_family_protocol_rules(self):
        fs=[f for f in self.compiled['graph'] if f['kind']=='filter']
        self.assertEqual([(x['family'],x['protocol']) for x in fs],[('v4','TCP'),('v4','UDP'),('v6','TCP'),('v6','UDP')])
        self.assertEqual([x['action'] for x in fs],['CALLOUT_TERMINATING_CANDIDATE','BLOCK_CANDIDATE']*2)
    def test_provider_and_callout_are_not_active(self):
        self.assertEqual(self.compiled['graph'][0]['native_status'],'NOT_PROVED')
        self.assertEqual(self.compiled['graph'][2]['registration'],'NOT_PROVED')
    def test_candidate_guards_not_real_proofs(self):
        self.assertIs(self.compiled['state_machine']['ready_observations_proven'],False)
        self.assertIs(self.compiled['state_machine']['state_names_are_model_only'],True)
    def test_static_identity_no_permit_exception(self):
        for ob in self.compiled['graph']:
            if ob['kind']=='filter':
                self.assertIs(ob['permit_if_callout_unregistered'],False)
                self.assertEqual(ob['match'],'ALE_ORIGINAL_APP_ID')
    def test_bad_release_promotion(self):self.bad_input(['release_accepted'],True)
    def test_bad_release_bool_int(self):self.bad_input(['release_accepted'],0)
    def test_bad_apply_permitted(self):self.bad_input(['apply_permitted'],True)
    def test_bad_apply_string(self):self.bad_input(['apply_permitted'],'false')
    def test_bad_schema_bool(self):self.bad_input(['schema'],True)
    def test_bad_schema_float(self):self.bad_input(['schema'],1.0)
    def test_bad_provider_enabled(self):self.bad_input(['provider','auto_start_verified'],True)
    def test_bad_provider_false_int(self):self.bad_input(['provider','auto_start_verified'],0)
    def test_bad_sublayer_key(self):self.bad_input(['sublayer','key'],'{deadbeef}')
    def test_bad_callout_key(self):self.bad_input(['callout','key'],'00112233-4455-6677-8899-aabbccddeeff')
    def test_bad_unregistered_permit(self):self.bad_input(['filters',0,'permit_if_callout_unregistered'],True)
    def test_bad_filter_false_as_int(self):self.bad_input(['filters',0,'permit_if_callout_unregistered'],0)
    def test_bad_opaque_appid(self):self.bad_input(['filters',1,'app_match'],'C:\\app.exe')
    def test_bad_action_tcp(self):self.bad_input(['filters',0,'action'],'FWP_ACTION_PERMIT')
    def test_bad_protocol_swap(self):self.bad_input(['filters',0,'protocol'],'UDP')
    def test_bad_layer_swap(self):self.bad_input(['filters',0,'layer'],'ALE_AUTH_CONNECT_V6')
    def test_bad_callback_downgrade(self):self.bad_input(['filters',0,'callout_unregistered_fallback'],'PERMIT')
    def test_bad_boot_handoff_promotion(self):self.bad_input(['boot_time_filter','pair_transition_proved'],True)
    def test_bad_native_hit_flag(self):self.bad_input(['filters',0,'native_hit_proof'],True)
    def test_bad_extra_filter(self):
        d=copy.deepcopy(self.ref);d['filters'].append(copy.deepcopy(d['filters'][0]))
        with self.assertRaises(m.GateError):m.compile_design(d,self.ref)
    def test_bad_extra_field(self):
        d=copy.deepcopy(self.ref);d['new_evidence']=True
        with self.assertRaises(m.GateError):m.compile_design(d,self.ref)
    def test_missing_field(self):
        d=copy.deepcopy(self.ref);del d['filters'][0]['action']
        with self.assertRaises(m.GateError):m.compile_design(d,self.ref)
    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(m.GateError):m.strict_load(b'{"schema":1,"schema":1}')
    def test_nan_json_rejected(self):
        with self.assertRaises(m.GateError):m.strict_load(b'{"s":NaN}')
    def test_bom_invalid(self):
        with self.assertRaises(m.GateError):m.strict_load(b'\xef\xbb\xbf'+m.R141.read_bytes())
    def test_oversize_rejected(self):
        with self.assertRaises(m.GateError):m.strict_load(b' '*65537)
    def test_reference_byte_change_rejected(self):
        original=m.R141
        with tempfile.TemporaryDirectory() as tmp:
            try:
                m.R141=Path(tmp)/'reference.json'
                m.R141.write_bytes(original.read_bytes()+b' ')
                with self.assertRaises(m.GateError):m.reference()
            finally:m.R141=original
    def test_forged_compiled_release_even_if_rehashed(self):self.bad_blueprint(['release_accepted'],True)
    def test_forged_compiled_appid_even_if_rehashed(self):self.bad_blueprint(['graph',4,'selected_appid'],'SENSITIVE_RAW_APPID')
    def test_forged_compiled_action_even_if_rehashed(self):self.bad_blueprint(['graph',4,'action'],'FWP_ACTION_PERMIT')
    def test_forged_compiled_family_even_if_rehashed(self):self.bad_blueprint(['graph',4,'family'],'v6')
    def test_forged_compiled_dependency_even_if_rehashed(self):self.bad_blueprint(['graph',4,'depends_on'],[])
    def test_forged_compiled_unregistered_flag_even_if_rehashed(self):self.bad_blueprint(['graph',4,'permit_if_callout_unregistered'],True)
    def test_forged_compiled_extra_object_field_even_if_rehashed(self):self.bad_blueprint(['graph',4,'installer_entrypoint'],'RunAsSystem')
    def test_forged_compiled_extra_top_field_even_if_rehashed(self):self.bad_blueprint(['run_command'],'FwpmFilterAdd0')
    def test_forged_compiled_ready_proof_even_if_rehashed(self):self.bad_blueprint(['state_machine','ready_observations_proven'],True)
    def test_forged_compiled_boot_continuity_even_if_rehashed(self):self.bad_blueprint(['boot_handoff','runtime_bfe_restart_coverage'],'PROVEN')
    def test_forged_compiled_incomplete_unresolved_even_if_rehashed(self):self.bad_blueprint(['unresolved'],[])
    def test_forged_compiled_recovery_executable_even_if_rehashed(self):self.bad_blueprint(['rollback_executable'],True)
    def test_forged_compiled_sha_without_rehash(self):
        d=copy.deepcopy(self.compiled);d['graph'][4]['layer']='ALE_AUTH_CONNECT_V6'
        with self.assertRaises(m.GateError):m.validate_blueprint(d)
    def test_model_matrix_count_and_only_one_candidate(self):
        rows=m.model_matrix().splitlines()
        self.assertEqual(len(rows),2048)
        self.assertEqual(sum(x.endswith('|1') for x in rows),1)
        self.assertEqual(rows[-1],'2047|1')
    def test_node_independent_full_matrix(self):
        x=json.loads(subprocess.check_output(['node',str(NODE)],text=True))
        self.assertEqual(x['states'],2048)
        self.assertEqual(x['simulated_ready_candidates'],1)
        self.assertEqual(x['native_acceptances'],0)
        self.assertIs(x['release_accepted'],False)
        self.assertEqual(x['sha256'],hashlib.sha256(m.model_matrix().encode()).hexdigest())
    def test_type_rejects_mask_bool(self):
        for v in (True,False,'0',1.0,-1,2048):
            with self.assertRaises(m.GateError):m.model_ready(v)
    def test_not_ready_with_one_missing_bit(self):
        for b in range(len(m.READY_OBSERVATIONS)):
            self.assertFalse(m.model_ready(m.ALL_READY ^ (1<<b)))
    def test_no_ready_from_blocking_baseline(self):
        self.assertEqual(m.transition('BLOCKING_BASELINE','WITNESS_READY',m.ALL_READY)['to'],'BLOCKING_BASELINE')
    def test_assemble_moves_to_recovery(self):
        self.assertEqual(m.transition('BLOCKING_BASELINE','ASSEMBLE')['to'],'RECOVERY')
    def test_incomplete_recovery_not_promoted(self):
        self.assertEqual(m.transition('RECOVERY','WITNESS_READY',m.ALL_READY-1)['to'],'RECOVERY')
    def test_complete_synthetic_recovery_candidate_only(self):
        x=m.transition('RECOVERY','WITNESS_READY',m.ALL_READY)
        self.assertEqual(x['to'],'VERIFIED_REDIRECT_READY')
        self.assertIs(x['actual_enforcement_proved'],False)
        self.assertIs(x['release_accepted'],False)
    def test_bfe_loss_is_uncertain_every_phase(self):
        for s in m.PHASES:
            x=m.transition(s,'BFE_LOSS')
            self.assertEqual(x['to'],'RECOVERY')
            self.assertTrue(x['continuity_unknown'])
            self.assertIs(x['actual_enforcement_proved'],False)
    def test_failures_from_ready_revoke(self):
        for event in m.FAILURES:
            if event!='BFE_LOSS':
                self.assertEqual(m.transition('VERIFIED_REDIRECT_READY',event)['to'],'REVOKING')
    def test_unobserved_revoke_not_claim_blocking(self):
        self.assertEqual(m.transition('REVOKING','REVOKE_COMPLETE')['to'],'RECOVERY')
    def test_observed_revoke_design_not_real_proof(self):
        x=m.transition('REVOKING','REVOKE_COMPLETE',independently_observed_baseline=True)
        self.assertEqual(x['to'],'BLOCKING_BASELINE')
        self.assertIs(x['actual_enforcement_proved'],False)
    def test_restart_requires_new_observation(self):
        for s in m.PHASES:
            self.assertEqual(m.transition(s,'RESTART',m.ALL_READY)['to'],'RECOVERY')
    def test_failures_never_native_proof(self):
        for phase in m.PHASES:
            for event in m.EVENTS:
                t=m.transition(phase,event,m.ALL_READY)
                self.assertIs(t['release_accepted'],False)
                self.assertIs(t['actual_enforcement_proved'],False)
    def test_invalid_phase_event(self):
        with self.assertRaises(m.GateError):m.transition('HACKED','ASSEMBLE')
        with self.assertRaises(m.GateError):m.transition('RECOVERY','INSTALL_FILTERS')
    def test_untyped_baseline(self):
        for v in ('false',0,1,None):
            with self.assertRaises(m.GateError):m.transition('RECOVERY','RECOVER_BASELINE',0,v)
    def test_python_optimized_rejects_mutation(self):
        altered=copy.deepcopy(self.ref);altered['filters'][0]['action']='FWP_ACTION_PERMIT'
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'bad.json';f.write_text(json.dumps(altered),encoding='utf-8')
            r=subprocess.run([sys.executable,'-O','-B',str(SOURCE),'--input',str(f)],
                             capture_output=True,text=True,timeout=10)
            self.assertNotEqual(r.returncode,0)
            self.assertIn('GateError',r.stderr)
    def test_command_line_file_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'output.json'
            subprocess.run([sys.executable,'-B',str(SOURCE),'--output',str(path)],check=True,timeout=10)
            self.assertEqual(path.read_bytes(),m.canonical_bytes(self.compiled))

if __name__=='__main__':unittest.main(verbosity=2)
