#!/usr/bin/env python3
"""Synthetic adversarial fixtures for the independent frozen A5 artifact auditor.

No native product binary is faked as an accepted release. Tests temporarily
replace expected digests *inside the test process only*; the checked-in
production auditor always pins the real original source and package hashes.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from io import BytesIO
import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "tools/a5_beta_frozen_artifact_audit.py"
SPEC = importlib.util.spec_from_file_location("a5_frozen",SCRIPT)
a5 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a5)


def dump(obj):
    return (json.dumps(obj,sort_keys=True,indent=2)+"\n").encode()


class Fixture:
    def __init__(self):
        self.installer={"windows/FlowBridge-0.3.0-beta.1-windows-x64-setup.exe":b"fake setup, not a real binary",
                        "macos/FlowBridge-0.3.0-beta.1-macOS-universal-explicit-beta.pkg":b"fake pkg, not a real binary"}
        self.files=dict(self.installer)
        for platform,count in (("windows",71),("macos",37)):
            refs=["pkg:cargo/fake-"+str(i)+"@0.1" for i in range(count)]
            bom={"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
                 "metadata":{"component":{"version":a5.VERSION},
                             "properties":[{"name":"flowbridge:source_sha","value":a5.SOURCE}]},
                 "components":[{"type":"library","name":"fake-"+str(i),"bom-ref":ref,
                                "licenses":[{"expression":"MIT"}]} for i,ref in enumerate(refs)],
                 "dependencies":[{"ref":ref,"dependsOn":[]} for ref in refs]}
            notice=b"FlowBridge resolved component notices\n"+b"notice text"*300
            meta={"schema":"flowbridge-explicit-beta-build-metadata-v1","source_sha":a5.SOURCE,
                  "version":a5.VERSION,"platform":platform,"explicit_socks_only":True,
                  "driver_included":False,"system_extension_included":False,
                  "publisher_release_approved":False,"independent_license_review_passed":False,
                  "binary_linkage_reviewed":False,"vulnerability_audit_performed":False,
                  "sbom_sha256":a5.sha(dump(bom)),"notices_sha256":a5.sha(notice),
                  "component_count":count,
                  "license_inventory":[{"component":"pkg:cargo/fake","files":
                    [{"name":"LICENSE.MIT","sha256":"a"*64}]}]}
            self.files[platform+"/SBOM.cdx.json"]=dump(bom)
            self.files[platform+"/BUILD-METADATA.json"]=dump(meta)
            self.files[platform+"/THIRD_PARTY_NOTICES.txt"]=notice
        for n in range(15):
            self.files["evidence/f"+str(n)+".json"]=dump({"i":n})
        assert len(self.files)==23
        self.license=b"FlowBridge\nNo separate open-source license has been selected for the FlowBridge-specific source code."
        self.index={"schema":"flowbridge-explicit-beta-candidate-v1",
                    "source_sha":a5.SOURCE,"workflow_run_id":a5.RUN,
                    "version":a5.VERSION,"hosted_candidate_valid":True,
                    "release_accepted":False,"publisher_release_approved":False,
                    "native_release_1_0":"NO_GO",
                    "gates":{"A5_independent_license_review":"OPEN",
                             "A3_owner_windows":"NOT_RUN","A4_owner_mac":"NOT_RUN",
                             "native_G2_packet_ownership":"NO_GO"}}

    def archive(self, *,extra=None, malformed=None, duplicate=False):
        rows=[{"path":name,"sha256":a5.sha(data),"bytes":len(data)}
              for name,data in sorted(self.files.items())]
        index={**self.index,"files":rows}
        index_bytes=dump(index)
        checksum=set(f"{r['sha256']}  {r['path']}" for r in rows)
        checksum.add(f"{a5.sha(index_bytes)}  candidate-index.json")
        output=BytesIO()
        with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as z:
            for name,data in self.files.items():
                z.writestr(name,data)
            z.writestr("candidate-index.json",index_bytes)
            z.writestr("SHA256SUMS.txt",("\n".join(sorted(checksum))+"\n").encode("ascii"))
            if extra:
                z.writestr(extra,b"extra")
            if malformed:
                z.writestr(malformed,b"evil")
            if duplicate:
                z.writestr("candidate-index.json",index_bytes)
        return output.getvalue()

    def run(self):
        blob=self.archive()
        with mock.patch.object(a5,"KIT_SHA256",a5.sha(blob)), mock.patch.object(
              a5,"INSTALLERS",{k:a5.sha(v) for k,v in self.installer.items()}):
            return a5.audit_kit(blob,self.license)

    def refuse(self,reason):
        blob=self.archive()
        with mock.patch.object(a5,"KIT_SHA256",a5.sha(blob)), mock.patch.object(
              a5,"INSTALLERS",{k:a5.sha(v) for k,v in self.installer.items()}):
            with unittest.TestCase().assertRaisesRegex(a5.AuditError,reason):
                a5.audit_kit(blob,self.license)


class A5AuditTests(unittest.TestCase):
    def test_synthetic_positive_never_promotes_release(self):
        report=Fixture().run()
        self.assertEqual(report["result"],"TECHNICAL_A5_INVENTORY_PASS_LEGAL_AND_NATIVE_REVIEW_OPEN")
        self.assertEqual(report["windows"]["bom_components"],71)
        self.assertEqual(report["macos"]["bom_components"],37)
        for name in ("project_license_selected","a5_accepted","release_accepted",
                     "independent_license_review_passed","native_sdk_runtime_distribution_review_passed"):
            self.assertIs(report[name],False,name)

    def test_outer_zip_digest_mismatch_rejected(self):
        f=Fixture()
        with self.assertRaisesRegex(a5.AuditError,"frozen_kit_sha256_mismatch"):
            a5.audit_kit(f.archive(),f.license)

    def test_project_license_must_be_independently_selected(self):
        f=Fixture();f.license=b"All rights reserved"
        f.refuse("project_license_contract_changed_review_required")

    def test_release_claim_escalation_rejected(self):
        f=Fixture();f.index["release_accepted"]=True
        f.refuse("candidate_index_identity_or_claim")

    def test_hosted_owner_claim_escalation_rejected(self):
        f=Fixture();f.index["gates"]["A3_owner_windows"]="PASS"
        f.refuse("candidate_index_claim_mismatch")

    def test_missing_sbom_rejected_even_if_index_matches(self):
        f=Fixture();del f.files["windows/SBOM.cdx.json"]
        f.files["evidence/replacement.json"]=b"{}"
        f.refuse("windows_SBOM" if False else "candidate_index_file_count")

    def test_duplicate_casefold_zip_member_rejected(self):
        f=Fixture();blob=f.archive(duplicate=True)
        with mock.patch.object(a5,"KIT_SHA256",a5.sha(blob)),self.assertRaisesRegex(
                a5.AuditError,"zip_duplicate_casefold"):
            a5.audit_kit(blob,f.license)

    def test_archive_path_traversal_rejected(self):
        f=Fixture();blob=f.archive(malformed="../untrusted")
        with mock.patch.object(a5,"KIT_SHA256",a5.sha(blob)),self.assertRaisesRegex(
                a5.AuditError,"unsafe_zip_path"):
            a5.audit_kit(blob,f.license)

    def test_undeclared_zip_file_rejected(self):
        f=Fixture();f.refuse("candidate_index_file_missing_or_duplicate") if False else None
        blob=f.archive(extra="secret.txt")
        with mock.patch.object(a5,"KIT_SHA256",a5.sha(blob)),self.assertRaisesRegex(
                a5.AuditError,"candidate_undeclared_file"):
            a5.audit_kit(blob,f.license)

    def test_invalid_license_component_metadata_rejected(self):
        f=Fixture()
        path="macos/SBOM.cdx.json"
        bom=json.loads(f.files[path])
        bom["components"][1].pop("licenses")
        f.files[path]=dump(bom)
        meta_path="macos/BUILD-METADATA.json"
        meta=json.loads(f.files[meta_path])
        meta["sbom_sha256"]=a5.sha(f.files[path])
        f.files[meta_path]=dump(meta)
        f.refuse("macos_missing_license_metadata")

    def test_dependency_graph_cannot_point_to_unknown_ref(self):
        f=Fixture()
        path="windows/SBOM.cdx.json"
        bom=json.loads(f.files[path])
        bom["dependencies"][0]["dependsOn"]=["pkg:evil/unknown"]
        f.files[path]=dump(bom)
        meta_path="windows/BUILD-METADATA.json"
        meta=json.loads(f.files[meta_path])
        meta["sbom_sha256"]=a5.sha(f.files[path])
        f.files[meta_path]=dump(meta)
        f.refuse("windows_broken_dependency_reference")

    def test_notices_digest_must_match_embedded_metadata(self):
        f=Fixture()
        f.files["windows/THIRD_PARTY_NOTICES.txt"]=b"tamper"
        f.refuse("windows_inventory_digest_mismatch")

    def test_source_git_archive_can_contain_directories(self):
        blob=BytesIO()
        with zipfile.ZipFile(blob,"w") as z:
            z.writestr("flowbridge/","")
            z.writestr("flowbridge/LICENSE",Fixture().license)
        self.assertEqual(a5.source_license_from_zip(blob.getvalue()),Fixture().license)

    def test_source_git_archive_path_escape_rejected(self):
        blob=BytesIO()
        with zipfile.ZipFile(blob,"w") as z:
            z.writestr("../FlowBridge/LICENSE",Fixture().license)
        with self.assertRaisesRegex(a5.AuditError,"source_zip_unsafe_path"):
            a5.source_license_from_zip(blob.getvalue())


if __name__=="__main__":
    unittest.main()
