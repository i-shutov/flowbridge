# Reproduce R143 (Linux / Windows; pure offline Python and Node)

At the repository root:

```sh
python -B research/wfp-ale/r143/test_r143.py
python -B research/wfp-ale/r143/r143_policy_compiler.py --output /tmp/FlowBridge-R143-BLUEPRINT.json
python -B research/wfp-ale/r143/r143_policy_compiler.py --model-matrix > /tmp/r143-model-matrix.txt
node research/wfp-ale/r143/r143_independent.mjs
```

On Windows change `/tmp/` to a local user-owned temporary path. No elevated
PowerShell is required. The `--output` option writes only a JSON dossier; it
never calls the WFP API or makes changes to filtering policy. `--input` accepts
only the *structurally identical* pinned R141 design-only JSON.

Expected: 71 Python tests PASS, 2048 matrix states, 1 synthetic ready candidate,
0 native acceptances, blueprint SHA256
`f1f08d056e88010fee2cf9bc4f47ea6e3dfc2af22231117a98bffda62f605ebb`.
If any SHA/condition differs, STOP and inspect; do not update golden digests
just to match an unexpected result.
