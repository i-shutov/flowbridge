import unittest
from pathlib import Path
from r187_safety_scan import SOURCE, audit


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SOURCE.read_text()

    def test_baseline(self):
        a = audit(self.text)
        self.assertTrue(a['safe'], a)
        self.assertEqual(a['violations'], [])
        self.assertEqual(a['missing'], [])

    def test_mutation_rejects_install_api(self):
        m = self.text.replace('FwpmFilterGetByKey0(', 'FwpmFilterAdd0(', 1)
        a = audit(m)
        self.assertFalse(a['safe'])
        self.assertIn('FwpmFilterAdd0', a['violations'])

    def test_mutation_rejects_driver_api(self):
        a = audit(self.text + '\nFwpsCalloutRegister1();')
        self.assertFalse(a['safe'])
        self.assertIn('FwpsCalloutRegister1', a['violations'])

    def test_mutation_rejects_writable_txn(self):
        m = self.text.replace('FwpmTransactionBegin0(engine.0, FWPM_TXN_READ_ONLY)',
                              'FwpmTransactionBegin0(engine.0, 0)', 1)
        a = audit(m)
        self.assertFalse(a['safe'])
        self.assertFalse(a['guards']['read_only_transaction'])

    def test_mutation_rejects_forged_go(self):
        a = audit(self.text + '\n// G2_PASS')
        self.assertFalse(a['safe'])

    def test_mutation_rejects_network_api(self):
        a = audit(self.text + '\nconnect();')
        self.assertFalse(a['safe'])
        self.assertIn('connect', a['violations'])


if __name__ == '__main__':
    unittest.main()
