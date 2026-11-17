"""Win32/Rust privacy source invariants (complements actual Rust runtime tests)."""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
SSH=(ROOT/"crates/flowbridge-tunnel/src/lib.rs").read_text(encoding="utf8")
GUI=(ROOT/"native/windows/main.cpp").read_text(encoding="utf8")

class TestSshSnapshotPrivacy(unittest.TestCase):
    def test_all_serialized_stderr_and_events_are_fixed_categories(self):
        begin=SSH.index("fn stderr_line(")
        end=SSH.index("#[cfg(unix)]\nfn prepare_stderr",begin)
        block=SSH[begin:end]
        self.assertIn("safe_ssh_stderr_summary(&lower)",block)
        self.assertIn("s.stderr.push_back(safe.into())",block)
        self.assertIn('s.event("warn", format!("ssh: {safe}"))',block)
        self.assertNotIn("s.stderr.push_back(text",block)
        self.assertNotIn('format!("ssh: {text}")',block)

    def test_ssh_identity_failure_classification_retained(self):
        begin=SSH.index("fn stderr_line(")
        end=SSH.index("#[cfg(unix)]\nfn prepare_stderr",begin)
        block=SSH[begin:end]
        self.assertIn('lower.contains("host key verification failed")',block)
        self.assertIn('lower.contains("permission denied (")',block)
        self.assertIn('s.fatal = Some(fatal.into())',block)
        self.assertIn('"ssh_resource_exhausted"',block)

    def test_native_gui_health_never_appends_backend_path_or_free_form_version(self):
        begin=GUI.index("void showSsh(")
        end=GUI.index("\nHWND control(",begin)
        text=GUI[begin:end]
        self.assertNotRegex(text,r'text\s*\+=\s*.*status\["backend_path"\]')
        self.assertNotRegex(text,r'text\s*\+=\s*.*status\["backend_version"\]')
        self.assertIn("ssh_status_presentation::append_health(events,text)",text)

    def test_export_path_uses_allowlisted_ffi_diagnostic_function(self):
        start=GUI.index("void exportDiagnostics(){")
        end=GUI.index("\nvoid ",start+2)
        block=GUI[start:end]
        self.assertIn("fb_diagnostic_report_json",block)
        self.assertNotIn('writeFile(path,latestSshSnapshot.dump()',block)
        self.assertNotIn('writeFile(path,ssh.dump()',block)

if __name__=="__main__":
    unittest.main()
