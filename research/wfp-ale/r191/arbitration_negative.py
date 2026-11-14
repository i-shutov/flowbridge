#!/usr/bin/env python3
"""R191 synthetic same-layer/cross-layer hard-permit negative experiment.
No WFP, network, drivers, system mutation, or actual packet inference.
"""
from __future__ import annotations
import csv, itertools, sys, unittest

FIELDS = ('family','bfe','protocol','app','attested','relative','foreign','layer','r19_hard','soft_counterfactual','classification')


def decide(family, bfe, protocol, app, attested, relative, foreign, layer, hard=True):
    assert family in ('v4','v6')
    if not bfe:
        return 'UNKNOWN_BFE_LOSS'
    if protocol != 'tcp' or app != 'selected':
        return 'OUT_OF_SCOPE'
    if not attested:
        return 'BLOCK_R19_AUTH'
    # Hypothetical *same-layer* arbitration; all layers still evaluate independently.
    if foreign == 'none' or foreign == 'permit':
        return 'PERMIT_MODEL'
    if layer == 'other':
        return 'BLOCK_OTHER_LAYER'
    if relative == 'higher':
        return 'BLOCK_HIGHER_SUBLAYER'
    if foreign == 'veto':
        return 'BLOCK_VETO'
    if foreign == 'block':
        return 'PERMIT_HARD_OVERRIDES_LOW_BLOCK' if hard else 'BLOCK_SOFT_LOW_BLOCK'
    raise AssertionError('invalid foreign outcome')


def rows():
    for family, bfe, protocol, app, attested, relative, foreign, layer in itertools.product(
        ('v4','v6'), (False, True), ('tcp','udp'), ('selected','sibling'),
        (False, True), ('higher','lower'), ('none','block','veto','permit'), ('same','other')):
        r19 = decide(family,bfe,protocol,app,attested,relative,foreign,layer,True)
        soft = decide(family,bfe,protocol,app,attested,relative,foreign,layer,False)
        yield (family, int(bfe), protocol, app, int(attested), relative, foreign, layer, r19, soft,
               'CANDIDATE_NOT_NATIVE_PROOF')


class NegativeTests(unittest.TestCase):
    def q(self, **kw):
        p=dict(family='v4',bfe=True,protocol='tcp',app='selected',attested=True,
               relative='lower',foreign='block',layer='same')
        p.update(kw)
        return decide(**p)
    def test_hard_permit_obscures_lower_plain_block(self):
        self.assertEqual(self.q(), 'PERMIT_HARD_OVERRIDES_LOW_BLOCK')
    def test_soft_control_differs(self):
        self.assertEqual(self.q(hard=False), 'BLOCK_SOFT_LOW_BLOCK')
    def test_higher_priority_block(self):
        self.assertEqual(self.q(relative='higher'), 'BLOCK_HIGHER_SUBLAYER')
    def test_lower_veto(self):
        self.assertEqual(self.q(foreign='veto'), 'BLOCK_VETO')
    def test_other_layer_independent(self):
        self.assertEqual(self.q(layer='other'), 'BLOCK_OTHER_LAYER')
    def test_unauthorized_auth_denies(self):
        self.assertEqual(self.q(attested=False), 'BLOCK_R19_AUTH')
    def test_sibling_udp_not_covered(self):
        self.assertEqual(self.q(app='sibling'), 'OUT_OF_SCOPE')
        self.assertEqual(self.q(protocol='udp'), 'OUT_OF_SCOPE')
    def test_bfe_loss_never_go(self):
        self.assertEqual(self.q(bfe=False), 'UNKNOWN_BFE_LOSS')
    def test_both_families_symmetric(self):
        self.assertEqual(self.q(family='v6'), self.q(family='v4'))
    def test_matrix_shape_and_counterexamples(self):
        data=list(rows())
        self.assertEqual(len(data),512)
        self.assertEqual(sum(x[8]!=x[9] for x in data), 2)
        self.assertEqual(sum(x[8]=='UNKNOWN_BFE_LOSS' for x in data),256)
        self.assertEqual(sum(x[8]=='OUT_OF_SCOPE' for x in data),192)

if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--csv':
        w=csv.writer(sys.stdout,lineterminator='\n')
        w.writerow(FIELDS)
        w.writerows(rows())
    else:
        unittest.main()
