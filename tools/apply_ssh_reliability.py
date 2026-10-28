from pathlib import Path
p=Path('tests/ssh_real_integration.py')
s=p.read_text(encoding='utf-8')
a="'verbose_diagnostics': True"
assert s.count(a)==1
s=s.replace(a,"'verbose_diagnostics': repetition % 2 == 1")
a='for repetition in range(10):'
assert s.count(a)==1
s=s.replace(a,'for repetition in range(20):')
p.write_text(s,encoding='utf-8')
print('Twenty isolated iterations, alternating normal and verbose SSH; first failure remains fatal')
