"""R97: pure deterministic falsification of the R95 WFP inventory layer gate.
No Windows APIs, drivers, sockets, WFP filters, or external packages.
"""
from hashlib import sha256
from pathlib import Path

LAYERS = ('AUTH_V4', 'AUTH_V6', 'REDIRECT_V4', 'REDIRECT_V6', 'OTHER')
EXPECTED = LAYERS[:4]


def source_guard() -> None:
    probe = Path(__file__).resolve().parents[1] / 'r93' / 'r93_readonly_policy_inventory.rs'
    policy = Path(__file__).resolve().parents[1] / 'kernel-r19' / 'policy_windows.rs'
    if not probe.is_file() or not policy.is_file():
        raise RuntimeError('source checkout required: R93 probe and R19 installer')
    a, b = probe.read_text(), policy.read_text()
    assert 'fv.layer_key == cv.applicable_layer' in a
    assert 'fn layer(r:Rule)->GUID' in b
    assert 'FWPM_LAYER_ALE_AUTH_CONNECT_V4' in b
    assert 'FWPM_LAYER_ALE_AUTH_CONNECT_V6' in b
    assert 'FWPM_LAYER_ALE_CONNECT_REDIRECT_V4' in b
    assert 'FWPM_LAYER_ALE_CONNECT_REDIRECT_V6' in b
    assert 'fv.layer_key == EXPECTED_LAYERS[i]' not in a


def matrix():
    for idx, expected in enumerate(EXPECTED):
        for filter_layer in LAYERS:
            for callout_layer in LAYERS:
                # Every other R95 gate is *assumed true*, isolating the layer check.
                old = filter_layer == callout_layer
                strict = filter_layer == expected and callout_layer == expected
                yield f'{idx},{expected},{filter_layer},{callout_layer},{int(old)},{int(strict)}'


def main():
    source_guard()
    lines = list(matrix())
    old = sum(int(x.rsplit(',', 2)[1]) for x in lines)
    strict = sum(int(x.rsplit(',', 1)[1]) for x in lines)
    fp = sum(x.endswith(',1,0') for x in lines)
    assert (len(lines), old, strict, fp) == (100, 20, 4, 16)
    digest = sha256(('\n'.join(lines) + '\n').encode()).hexdigest()
    print(f'cases={len(lines)} r95_gate_accepts={old} strict_layer_accepts={strict} false_positives={fp}')
    print('matrix_sha256=' + digest)


if __name__ == '__main__':
    main()
