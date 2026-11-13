#!/usr/bin/env python3
"""FlowBridge explicit-only macOS candidate: source and package safety checks.

Read-only, no installation, no network, no extension activation. Run on Linux
for static validation, and on hosted macOS with --app/--pkg for real payload QA.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
PRODUCT="FlowBridgeExplicitBeta"
BUNDLE="org.flowbridge.FlowBridgeExplicitBeta"
MACRO="FLOWBRIDGE_EXPLICIT_BETA_ONLY"
PROTECTED=("systemextension","networkextension","launchdaemons","privilegedhelpertools",
           "flowbridgecapture.exe",".sys",".inf")

def require(ok:bool,why:str)->None:
    if not ok: raise RuntimeError(why)

def load(path:str)->str:
    p=ROOT/path
    require(p.is_file(),"Missing source: "+path)
    return p.read_text(encoding="utf-8")

def source_gate()->dict:
    # Content checks deliberately examine compiled BUILD TARGET and the controller
    # call sites, not merely a README or a forged release-report boolean.
    yaml=load("native/macos/project.yml")
    try:
        import yaml as pyyaml
    except ModuleNotFoundError:
        # Hosted native job has XcodeGen, but PyYAML need not be preinstalled.
        # Fail closed if parser unavailable; no fake static PASS.
        raise RuntimeError("Python PyYAML is required for static scheme audit")
    cfg=pyyaml.safe_load(yaml)
    targets=cfg["targets"]
    require(PRODUCT in targets,"Missing isolated app target")
    beta=targets[PRODUCT]
    require(beta.get("templates")==["AppBase"],"Explicit beta target not from AppBase")
    require(not beta.get("dependencies"),"Explicit beta has target dependency")
    settings=beta["settings"]["base"]
    require(settings["PRODUCT_NAME"]==PRODUCT,"Incorrect beta executable")
    require(settings["PRODUCT_BUNDLE_IDENTIFIER"]==BUNDLE,"Incorrect beta bundle ID")
    require(MACRO in settings["SWIFT_ACTIVE_COMPILATION_CONDITIONS"],"No compile-time scope guard")
    require(settings["CODE_SIGN_IDENTITY"]=="-" and settings["CODE_SIGN_STYLE"]=="Manual","Beta must be ad-hoc local-only")
    require("CODE_SIGN_ENTITLEMENTS" not in settings,"Explicit beta requests entitlements")
    require(cfg["schemes"][PRODUCT]["build"]["targets"]=={PRODUCT:"all"},"Scheme builds an extra target")
    require("FlowBridgeExtension" not in str(beta),"Extension accidentally referenced")
    require(cfg["targets"]["FlowBridge"]["dependencies"],"Native scheme accidentally removed")
    require(cfg["targets"]["FlowBridgeLocal"]["templates"]==["AppBase"],"Historical local target modified")

    desktop=load("native/macos/App/DesktopController.swift")
    engine=load("native/macos/App/EngineController.swift")
    app=load("native/macos/App/FlowBridgeApp.swift")
    native=load("native/macos/App/NativeController.swift")
    for name,text in (("DesktopController",desktop),("EngineController",engine),("FlowBridgeApp",app)):
        require(MACRO in text,name+" missing compile guard")
    for path,text in (("desktop.json",desktop),("profile.json",engine)):
        require(f'FlowBridgeExplicitBeta/{path}' in text and f'FlowBridge/{path}' in text,
                "Profile namespace crossover: "+path)
    for action in ("func start()","func apply()","func saveSettings()","private func configuredProfile()"):
        pos=desktop.find(action)
        require(pos>=0 and MACRO in desktop[pos:pos+450],
                "Missing guarded runtime entry: "+action)
    require("settings.mode = 0" in desktop and "guard settings.mode == 0" in desktop,
            "Forged native-mode preference may survive beta load")
    require('WindowGroup(productTitle)' in app and "FlowBridge Explicit Beta" in app,
            "Stable app identity reused")
    require('Label("Только локальный SOCKS5' in app and '#else\n                    Picker("Режим"' in app,
            "Transparent mode must not be selectable in explicit beta")
    require("#if FLOWBRIDGE_NATIVE" in native and "Transparent capture unavailable in this local SOCKS build." in native,
            "No explicit-only native stub")

    build=load("packaging/macos/build-app.sh")
    pkg=load("packaging/macos/build-pkg.sh")
    require("explicit-beta) scheme=FlowBridgeExplicitBeta" in build,"Build script cannot select isolated scheme")
    require('test ! -d "$app/Contents/Library/SystemExtensions"' in build,"No extension absence gate")
    require("com.apple.developer.networking.networkextension" in build,"No NE entitlement exclusion")
    require('product="FlowBridgeExplicitBeta"' in pkg and 'pkgutil --payload-files "$result"' in pkg,
            "Package does not inspect actual payload")
    require('pkg_identifier="org.flowbridge.FlowBridgeExplicitBeta.installer"' in pkg,
            "Package may replace stable receipt")
    forbidden=("systemextensions","privilegedhelpertools")
    for word in forbidden:
        require(word.lower() in pkg.lower(),"Missing forbidden path check: "+word)
    return {"source_gate":True,"target":PRODUCT,"bundle_id":BUNDLE,
            "profile_namespaced":True,"native_mode_compile_guard":True,
            "system_extension_build_dependency":False,"release_accepted":False}

def subprocess_text(args:list[str])->str:
    r=subprocess.run(args,text=True,capture_output=True,timeout=45,check=False)
    require(r.returncode==0,f"{args[0]} failed ({r.returncode}): {r.stderr[-600:]}")
    return r.stdout

def package_gate(app:Path,pkg:Path)->dict:
    require(sys.platform=="darwin","Native .app/.pkg acceptance requires macOS")
    app=app.resolve(strict=True);pkg=pkg.resolve(strict=True)
    require(app.name==PRODUCT+".app","Expected isolated app bundle")
    info=plistlib.loads((app/"Contents/Info.plist").read_bytes())
    require(info["CFBundleIdentifier"]==BUNDLE,"Installed app bundle ID mismatched")
    require(info["CFBundleExecutable"]==PRODUCT,"Executable inside app not isolated")
    sys.path.insert(0, str(ROOT / "tools"))
    from explicit_beta_metadata import read_contract
    from explicit_beta_candidate import validate_inventory
    version = read_contract()
    require(info.get("CFBundleShortVersionString") == version["macos_short_version"] and
            info.get("CFBundleVersion") == version["macos_bundle_version"] and
            info.get("FlowBridgeVersion") == version["version"], "Beta app version mismatch")
    source = subprocess_text(["git", "rev-parse", "HEAD"]).strip()
    validate_inventory(app / "Contents/Resources", source, version["version"], "macos")
    require(not (app/"Contents/Library/SystemExtensions").exists(),"System extension present in beta app")
    require(not (app/"Contents/PlugIns").exists(),"Plugin present in beta app")
    archs=subprocess_text(["xcrun","lipo","-archs",str(app/"Contents/MacOS"/PRODUCT)]).split()
    require({"arm64","x86_64"}<=set(archs),"Universal Mac binary absent")
    subprocess_text(["codesign","--verify","--deep","--strict",str(app)])
    e=subprocess.run(["codesign","-d","--entitlements",":-",str(app)],
                     capture_output=True,text=True,timeout=45,check=False)
    # An ad-hoc app can have no entitlements, which codesign reports as error or empty.
    ent=e.stdout+e.stderr
    for k in ("com.apple.developer.networking.networkextension",
              "com.apple.developer.system-extension.install"):
        require(k not in ent,"Forbidden entitlement: "+k)
    listing=subprocess_text(["pkgutil","--payload-files",str(pkg)]).splitlines()
    require(listing and any(PRODUCT+".app/" in item for item in listing),
            "Package is missing explicit beta app")
    for item in listing:
        lower=item.lower()
        require(not any(word in lower for word in PROTECTED),
                "Forbidden payload: "+item)
        require("flowbridge.app/" not in lower,"Stable FlowBridge app bundled")
        require(item in (".","./","Applications","./Applications") or
                item.startswith("./Applications/") or item.startswith("Applications/"),
                "Package has non-application payload: "+item)
    return {"native_package_gate":True,"bundle_id":BUNDLE,"binary_arches":sorted(archs),
            "payload_entries":len(listing),"pkg_sha256":hashlib.sha256(pkg.read_bytes()).hexdigest(),
            "extension_present":False,"release_accepted":False}

def main()->None:
    ap=argparse.ArgumentParser()
    ap.add_argument("--app",type=Path)
    ap.add_argument("--pkg",type=Path)
    ap.add_argument("--out",type=Path)
    opts=ap.parse_args()
    require((opts.app is None)==(opts.pkg is None),"Supply BOTH app and pkg for native test")
    result={"schema":"flowbridge-explicit-beta-macos-scope-v1",**source_gate(),
            "source_sha":subprocess_text(["git","rev-parse","HEAD"]).strip(),
            "source_tree_sha":subprocess_text(["git","rev-parse","HEAD^{tree}"]).strip(),
            "workflow_run_id":os.environ.get("GITHUB_RUN_ID")}
    if opts.app is not None: result.update(package_gate(opts.app,opts.pkg))
    else: result["native_package_gate"]="NOT_RUN"
    payload=json.dumps(result,sort_keys=True,indent=2)+"\n"
    if opts.out:
        opts.out.parent.mkdir(parents=True,exist_ok=True)
        opts.out.write_text(payload,encoding="utf-8")
    print(payload,end="")

if __name__=="__main__":
    main()
