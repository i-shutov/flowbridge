# Reproduce R138

From repository/checkpoint root:

```sh
python research/wfp-ale/r138/r138_acceptance.py
python research/wfp-ale/r138/r138_oracle.py
node research/wfp-ale/r138/r138_independent.mjs
python research/wfp-ale/r138/validate_r137_archive.py /path/to/evidence-only\(3\).zip
```

Only the last command needs the original private owner archive; it is not published.
Prior validation modules in research/wfp-ale/r137 are hash-pinned dependencies.
Windows: parse the pinned PS1 first, then run it with -RunOwnSiblingProbe using an
already installed native x64 MSVC Rust compiler. No clone or installation necessary.
Without the flag it executes synthetic tests only. -CompileOnly checks metadata.

Expected new runtime results remain NOT_RUN until the owner supplies R138 logs.
SHA manifest in the checkpoint covers exact source bytes. Never normalize CRLF or
BOM to bypass the source hash. Runtime matrix stdout alone may normalize CRLF to LF.
