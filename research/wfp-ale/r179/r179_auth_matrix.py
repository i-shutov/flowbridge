"""R179 offline-only synthetic predicate; NOT native WFP proof."""
import itertools, json
from collections import Counter

items = []
for family, leg, original, current, flags, target in itertools.product(
    (4, 6), ('accepted_redirect', 'physical_ssh', 'sibling_direct'),
    ('selected', 'broker'), ('selected', 'broker'),
    ('none', 'redirect', 'proxy', 'both'), (False, True)
):
    # policy_windows: AUTH filter scoped only to original selected AppId + TCP.
    if original != 'selected': result = 'OUTSIDE_FILTER'
    elif leg == 'accepted_redirect' and flags in ('redirect', 'both') and target:
        result = 'PERMIT_MODEL_ONLY'
    else: result = 'BLOCK'
    items.append(dict(family=family, leg=leg, original=original,
                      current=current, flags=flags, target=target, result=result))
counts = Counter(x['result'] for x in items)
assert len(items) == 192 and counts == dict(BLOCK=88, OUTSIDE_FILTER=96, PERMIT_MODEL_ONLY=8)
assert sum(x['leg']=='physical_ssh' and x['original']=='selected' and x['result']=='BLOCK' for x in items)==32
for row in items: print(json.dumps(row, sort_keys=True, separators=(',', ':')))
