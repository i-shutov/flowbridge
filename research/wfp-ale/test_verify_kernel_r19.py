"""Offline adversarial artifact-reader tests. Never loads the driver."""
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest
import zipfile
import verify_kernel_r19 as v

class ReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kp = os.environ.get('FLOWBRIDGE_R19_KERNEL_ZIP')
        sp = os.environ.get('FLOWBRIDGE_R19_SOCKET_ZIP')
        if not kp or not sp:
            raise unittest.SkipTest('Pinned artifacts not supplied; no native acceptance')
        cls.k = Path(kp).read_bytes(); cls.s = Path(sp).read_bytes()
        with zipfile.ZipFile(kp) as z: cls.d = z.read('flowbridge_g2_witness.sys')
        cls.p = struct.unpack_from('<I', cls.d, 60)[0]; cls.o = cls.p+24
    def mutate(self, off, fmt, value):
        b=bytearray(self.d);struct.pack_into(fmt,b,off,value);return bytes(b)
    def test_actual_downloaded_bytes_and_scope(self):
        out=v.audit(self.k,self.s)
        self.assertEqual(out['driver_bytes'],198144)
        self.assertFalse(out['g2_pass'])
        self.assertFalse(out['kernel_driver_loaded'])
        self.assertFalse(out['pe']['embedded_certificate_present'])
    def test_tampered_archive_rejected(self):
        b=bytearray(self.k);b[-1]^=1
        with self.assertRaises(v.Rejected):v.audit(bytes(b),self.s)
    def test_tampered_socket_zip_rejected(self):
        with self.assertRaises(v.Rejected):v.audit(self.k,self.s+b' ')
    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(v.Rejected):v.decode(b'{"ok":true,"ok":false}')
    def test_bad_pe_machine_rejected(self):
        with self.assertRaisesRegex(v.Rejected,'pe_x64'):v.PE(self.mutate(self.p+4,'<H',0x14c))
    def test_user_mode_subsystem_rejected(self):
        with self.assertRaisesRegex(v.Rejected,'pe_not_native'):v.PE(self.mutate(self.o+68,'<H',3))
    def test_integrity_and_nx_required(self):
        flags=struct.unpack_from('<H',self.d,self.o+70)[0]
        for bit in (0x80,0x100):
            with self.subTest(bit=bit),self.assertRaises(v.Rejected):v.PE(self.mutate(self.o+70,'<H',flags&~bit))
    def test_no_certificate_acceptance_inferred(self):
        with self.assertRaisesRegex(v.Rejected,'unexpected_embedded_certificate'):
            v.PE(self.mutate(self.o+112+4*8,'<I',128))
    def test_zero_entrypoint_rejected(self):
        with self.assertRaisesRegex(v.Rejected,'entry_not_executable'):v.PE(self.mutate(self.o+16,'<I',0))
    def test_writable_executable_section_rejected(self):
        header=self.o+struct.unpack_from('<H',self.d,self.p+20)[0]
        flags=struct.unpack_from('<I',self.d,header+36)[0]
        with self.assertRaisesRegex(v.Rejected,'writable_executable'):v.PE(self.mutate(header+36,'<I',flags|0x80000000))
    def test_out_of_range_section_rejected(self):
        header=self.o+struct.unpack_from('<H',self.d,self.p+20)[0]
        with self.assertRaisesRegex(v.Rejected,'section_outside'):v.PE(self.mutate(header+20,'<I',len(self.d)+100))
    def test_invalid_import_rva_rejected(self):
        with self.assertRaises(v.Rejected):v.PE(self.mutate(self.o+120,'<I',0xffffffff))
    def test_foreign_runtime_dll_rejected(self):
        p=v.PE(self.d);p.imports['user32.dll']=[]
        with self.assertRaisesRegex(v.Rejected,'runtime_library'):p.summary()
    def test_missing_birth_callback_import_rejected(self):
        p=v.PE(self.d);p.imports['ntoskrnl.exe'].remove('PsSetCreateProcessNotifyRoutineEx')
        with self.assertRaisesRegex(v.Rejected,'witness_api'):p.summary()
    def test_redirect_mutation_cannot_be_labelled_observer(self):
        p=v.PE(self.d);p.imports['fwpkclnt.sys'].append('FwpsApplyModifiedLayerData0')
        with self.assertRaisesRegex(v.Rejected,'redirect_mutation'):p.summary()

if __name__=='__main__':unittest.main(verbosity=2)
