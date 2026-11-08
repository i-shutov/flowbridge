"""Fail-closed regression tests for exact committed R39 Cargo lockfiles."""
import tempfile,unittest
from pathlib import Path
from locks_r39 import EXPECTED,verify_pinned

ROOT=Path(__file__).resolve().parent
class LockProvenance(unittest.TestCase):
    def fixture(self):
        tmp=tempfile.TemporaryDirectory(prefix="flowbridge-r39-lock-")
        root=Path(tmp.name)
        for name in EXPECTED:
            target=root/name
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes((ROOT/name).read_bytes())
        return tmp,root

    def test_real_exact_committed_locks(self):
        proof=verify_pinned(ROOT)
        self.assertTrue(proof["lockfiles_exact_from_original_ci"])
        self.assertEqual(len(proof["lockfiles"]),2)
        self.assertEqual(sum(x["packages"] for x in proof["lockfiles"].values()),212)

    def test_single_byte_source_mutation_denied(self):
        t,root=self.fixture()
        with t:
            path=root/"broker-package/Cargo.lock"
            data=bytearray(path.read_bytes())
            data[100]^=1
            path.write_bytes(data)
            with self.assertRaisesRegex(RuntimeError,"dependency drift"):
                verify_pinned(root)

    def test_missing_kernel_lock_denied(self):
        t,root=self.fixture()
        with t:
            (root/"kernel/Cargo.lock").unlink()
            with self.assertRaises(FileNotFoundError):
                verify_pinned(root)

    def test_truncated_lock_denied(self):
        t,root=self.fixture()
        with t:
            path=root/"broker-package/Cargo.lock"
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaisesRegex(RuntimeError,"dependency drift"):
                verify_pinned(root)

    def test_spliced_lock_with_same_size_denied(self):
        t,root=self.fixture()
        with t:
            a=root/"broker-package/Cargo.lock"
            b=a.read_bytes()
            a.write_bytes(b[1:]+b[:1])
            with self.assertRaisesRegex(RuntimeError,"dependency drift"):
                verify_pinned(root)
if __name__=="__main__":
    unittest.main()
