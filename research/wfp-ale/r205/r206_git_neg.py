#!/usr/bin/env python3
"""R206 POSIX path-alias negative oracle. No WFP/Windows calls."""
import tempfile
from pathlib import Path

def outside(root, target):
    r, t = root.absolute(), target.absolute()
    return t != r and r not in t.parents

def safe(root, target):
    if not outside(root, target): return False
    return not any(p.is_symlink() for x in (root, target) for p in (x, *x.parents))

with tempfile.TemporaryDirectory() as tmp:
    b = Path(tmp); repo = b/'repo'; repo.mkdir(); (repo/'empty').mkdir()
    external = b/'external'
    assert outside(repo,external) and safe(repo,external)
    assert not outside(repo,repo/'empty') and not safe(repo,repo/'empty')
    leaf = b/'leaf'; leaf.symlink_to(repo/'empty',target_is_directory=True)
    parent = b/'parent'; parent.symlink_to(repo,target_is_directory=True)
    alias = b/'repo-alias'; alias.symlink_to(repo,target_is_directory=True)
    for base, dest in [(repo,leaf),(repo,parent/'empty'),(alias,repo/'empty')]:
        assert outside(base,dest) and not safe(base,dest)
        assert dest.resolve().is_relative_to(repo.resolve())
print('R206-PY: 5/5 PASS, real POSIX symlink counterexamples; NOT Windows')
