#!/usr/bin/env python3
import dataclasses
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('preflight',ROOT/'r141_preflight.py')
import sys
p=importlib.util.module_from_spec(spec);sys.modules['preflight']=p;spec.loader.exec_module(p)
spec2=importlib.util.spec_from_file_location('oracle',ROOT/'r141_lifetime_oracle.py')
o=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(o)

spec3=importlib.util.spec_from_file_location('descriptor',ROOT/'r141_descriptors.py')
d=importlib.util.module_from_spec(spec3);spec3.loader.exec_module(d)

class TestR141(unittest.TestCase):
    def test_descriptor_does_not_install(self):
        doc=d.build();d.validate(doc)
        self.assertIs(doc['apply_permitted'],False)
        self.assertEqual(doc['kind'],'NON_INSTALLABLE_DESIGN_ONLY')
    def test_descriptor_exposes_four_selected_families(self):
        doc=d.build();self.assertEqual(len(doc['filters']),4)
        self.assertEqual({f['name'] for f in doc['filters']},
                         {'selected_tcp_v4','selected_tcp_v6','selected_udp_v4','selected_udp_v6'})
    def test_descriptor_excludes_unregistered_permit(self):
        self.assertFalse(any(f['permit_if_callout_unregistered'] for f in d.build()['filters']))
    def test_descriptor_does_not_claim_socket_proof(self):
        self.assertFalse(d.build()['native_accepted_socket_to_ssh_proved'])
    def test_descriptor_refuses_mutated_permit_fallback(self):
        x=d.build();x['filters'][0]['permit_if_callout_unregistered']=True
        with self.assertRaises(AssertionError):d.validate(x)
    def test_descriptor_refuses_scope_loss(self):
        x=d.build();x['filters'].pop()
        with self.assertRaises(AssertionError):d.validate(x)
    def test_no_concrete_add_api_or_guid_bytes(self):
        s=(ROOT/'r141_descriptors.py').read_text()
        for bad in ('FwpmFilterAdd0(', 'FwpmEngineOpen0(', 'CreateFileW(', 'FWPM_FILTER_FLAG_BOOTTIME | FWPM_FILTER_FLAG_PERSISTENT'):
            self.assertNotIn(bad,s)
    def test_r19_no_go(self):
        r=p.evaluate(p.r19_source_snapshot())
        self.assertEqual(r['status'],'NOT_DEPLOYABLE')
        self.assertIn('lifetime_not_persistent',r['blockers'])
    def test_r19_appid_tcp_only(self):
        c=p.r19_source_snapshot()
        self.assertTrue(c.selected_app_v4_tcp and c.selected_app_v6_tcp)
        self.assertFalse(c.selected_app_v4_udp or c.selected_app_v6_udp)
    def test_naive_hard_block_breaks_selected_route(self):
        r=p.evaluate(p.naive_persistent_block())
        self.assertIn('hard_block_can_break_redirect',r['blockers'])
    def test_naive_appid_or_pid_exception_rejected(self):
        r=p.evaluate(p.naive_persistent_block())
        self.assertIn('path_or_pid_only_exception_unsafe',r['blockers'])
    def test_permit_if_callout_missing_is_unacceptable(self):
        c=dataclasses.replace(p.naive_persistent_block(),permit_if_callout_unregistered=True)
        self.assertIn('fail_open_when_callout_missing',p.evaluate(c)['blockers'])
    def test_all_flags_still_not_release_proof(self):
        c=p.Candidate(**{f.name:('persistent' if f.name=='lifetime' else True) for f in dataclasses.fields(p.Candidate)})
        r=p.evaluate(c)
        self.assertFalse(r['release_accepted']);self.assertFalse(r['native_wfp_executed'])
        self.assertFalse(r['no_direct_proved'])
    def test_clear_dossier_not_release(self):
        d={f.name:True for f in dataclasses.fields(p.Candidate) if f.name!='lifetime'}
        d.update(lifetime='persistent',permit_if_callout_unregistered=False,hard_block_without_proven_exception=False,path_or_pid_only_exception=False)
        r=p.evaluate(p.Candidate(**d))
        self.assertEqual(r['blockers'],[])
        self.assertEqual(r['status'],'DOSSIER_READY_FOR_INDEPENDENT_LAB_REVIEW_ONLY')
        self.assertFalse(r['release_accepted'])
    def test_one_missing_boolean_always_blocks(self):
        d={f.name:True for f in dataclasses.fields(p.Candidate) if f.name!='lifetime'}
        d.update(lifetime='persistent',permit_if_callout_unregistered=False,hard_block_without_proven_exception=False,path_or_pid_only_exception=False)
        for field in dataclasses.fields(p.Candidate):
            if field.name in ('lifetime','permit_if_callout_unregistered','hard_block_without_proven_exception','path_or_pid_only_exception'):continue
            altered=p.Candidate(**{**d,field.name:False})
            self.assertTrue(p.evaluate(altered)['blockers'],field.name)
    def test_ordered_unique_blocker_codes(self):
        self.assertEqual(len(set(p.BLOCKERS)),len(p.BLOCKERS))
        self.assertEqual(p.evaluate(p.Candidate())['blockers'],[b for b in p.BLOCKERS if b not in ('fail_open_when_callout_missing','hard_block_can_break_redirect','path_or_pid_only_exception_unsafe')])
    def test_boolean_strings_and_integers_rejected(self):
        for field in dataclasses.fields(p.Candidate):
            if field.name=='lifetime':continue
            for corrupt in ('false','true',0,1,None):
                with self.subTest(field=field.name,corrupt=corrupt):
                    with self.assertRaises(TypeError):p.evaluate(dataclasses.replace(p.Candidate(),**{field.name:corrupt}))
    def test_unknown_lifetime_rejected(self):
        for life in ('unknown','',0,True,'PERSISTENT'):
            with self.assertRaises(ValueError):p.evaluate(dataclasses.replace(p.Candidate(),lifetime=life))
    def test_source_cannot_label_any_unobserved_state_enforced(self):
        s=(ROOT/'r141_lifetime_oracle.py').read_text()
        self.assertNotIn('RELEASE_GO',s)
        self.assertNotIn('FwpmFilterAdd0(',s)
    def test_wrong_candidate_type(self):
        for value in (None,{},1,True):
            with self.assertRaises(TypeError):p.evaluate(value)
    def test_lifecycle_oracle_192_states(self):
        self.assertEqual(o.summary()['scenarios'],192)
    def test_independent_node_model_agreement(self):
        j=json.loads(subprocess.check_output(['node',str(ROOT/'r141_lifetime_independent.mjs')],text=True))
        self.assertEqual(j,o.summary())
    def test_dynamic_owner_death_absent(self):
        for a in (0,1):
            for b in (0,1):
                self.assertEqual(o.status('dynamic','owner_exited',a,b,0),'missing')
    def test_static_goes_away_on_bfe_down(self):
        self.assertEqual(o.status('static','bfe_runtime_down',1,1,0),'missing')
    def test_persistent_survives_as_stored_not_enforced(self):
        self.assertEqual(o.status('persistent','bfe_runtime_down',1,1,0),'stored_only')
    def test_boot_only_not_reinstated_on_bfe_runtime_crash(self):
        self.assertEqual(o.status('boot_time','bfe_runtime_down',1,1,0),'missing')
    def test_boot_and_persistent_flags_not_combinable(self):
        s=(ROOT/'R141_PERSISTENT_GATE_ARCHITECTURE.md').read_text()
        self.assertIn('cannot combine BOOTTIME and PERSISTENT',s)
    def test_callout_missing_fail_open_is_visible(self):
        self.assertEqual(o.status('persistent','owner_exited',1,0,1),'callout_unregistered_permit_fallback')
    def test_callout_missing_default_block_documented(self):
        self.assertEqual(o.status('persistent','owner_exited',1,0,0),'callout_unregistered_block_fallback')
    def test_provider_disabled_never_candidate_enforced(self):
        self.assertEqual(o.status('persistent','bfe_active',0,1,0),'provider_disabled_or_unverified')
    def test_no_matrix_entry_claims_effective_enforcement(self):
        self.assertTrue(all(row.rstrip().endswith('|0') for row in o.matrix()))
    def test_relevant_repository_source_pins(self):
        import re
        s=(ROOT/'R141_PERSISTENT_GATE_ARCHITECTURE.md').read_text()
        self.assertIn('acf60334320d970f58af3349ee75fbaa59826602',s)
        self.assertIn('c8ab344551f1adfc20fd0019c4606cf3ca3c81c4',s)
        self.assertIn('FWPM_SESSION_FLAG_DYNAMIC',s)
    def test_canary_disabled_provider_is_rejected(self):
        c=dataclasses.replace(p.naive_persistent_block(),provider_enabled_after_bfe_start=False)
        self.assertIn('provider_activation_unproven',p.evaluate(c)['blockers'])
    def test_pure_offline_static_scope(self):
        for file in ('r141_preflight.py','r141_lifetime_oracle.py','r141_lifetime_independent.mjs'):
            s=(ROOT/file).read_text()
            for word in ('CreateFileW','FwpmFilterAdd0(', 'FwpmEngineOpen0(', 'TerminateProcess(', 'socket.connect('):self.assertNotIn(word,s)
    def test_exact_deterministic_hash(self):
        self.assertEqual(o.summary()['sha256'],'5b99f8a5d2147bb8f54704dbeec81fb89dbe30a684b19376236d1abe5651f4bf')
    def test_no_architecture_document_claims_go(self):
        s=(ROOT/'R141_PERSISTENT_GATE_ARCHITECTURE.md').read_text()
        self.assertIn('RELEASE NO-GO',s)

if __name__=='__main__':unittest.main(verbosity=2)
