# Explicit OpenSSH backend selection — internal beta gate

2026-10-29. A change requested under [#7](https://github.com/i-shutov/flowbridge/issues/7)
after observed Windows `ssh -D` channel exhaustion around 251–252 channels.

## User behavior and security constraints

* The **Windows Connection → Managed SSH** page has a compact optional
  `ssh.exe` path field, one local .exe picker and the existing SSH
  compression checkbox on the same row. The field defaults empty and is saved
  as `ssh.ssh_executable` in `desktop-settings.json`.
* Empty means the existing **absolute PATH-directory search**; no change to
  existing users. Selecting an explicit backend requires an **absolute local
  file path**. Relative names, UNC/network paths, non-.exe candidates, control
  characters, oversized paths and option/URI-like values fail validation.
* The Rust supervisor canonicalizes the selected path and rejects a missing
  file. Before opening a dynamic listener it runs `<selected.exe> -V` and
  requires an `OpenSSH_` identification from its stderr. If the selected file
  fails this compatibility check, supervision is permanently failed: there is
  **no automatic fallback to PATH or another executable**.
* GUI tests verify two-way persistence and rejection of a relative filename,
  while Rust tests check local/absolute-path conditions, non-OpenSSH rejection
  and no inadvertent restart.
* The chosen executable **runs without UAC under the normal user**. An
  explicitly selected binary is untrusted until the operator verifies the
  file's provenance/signature independently. The `-V` output identifies a
  version string; **it is not a code-signature or publisher check**.
* The existing hardened `-F none`, strict host-key validation, public-key
  authentication only, `BatchMode`, `ControlMaster=no`, disabled password
  prompts, and managed restart/backoff options are unchanged.
* Changing executable path requires stopping the managed SSH session first;
  established TCP streams remain tied to their original SSH process and
  are never transparently migrated.
* On **macOS**, an explicit alternate binary is rejected unless it resolves
  to the system `/usr/bin/ssh`, because native Network Extension loop
  prevention depends on that binary's known signing identity. This is not
  a promise of actual NE activation.

## Evidence and release boundary

Hosted CI can test validation, native GUI field persistence/layout, packaged
OpenSSH defaults and cross-platform builds. It does **not** demonstrate that a
specific Git for Windows SSH binary is compatible with all startup flags,
uses a higher file-descriptor ceiling, or safely supports more channels.
The observed Windows `MAX_FDS` incident still requires **real isolated
Windows** measurements at 64/128/192/256/512 concurrent TCP flows, version
and actual absolute path logging, CPU/memory/handle/socket accounting and
fail-closed recovery. A path/version appearing in diagnostics should not be
taken as proof of signature or backend resource limits.

No private keys are uploaded by this test, and no user SSH client is
automatically installed, downloaded or replaced.
