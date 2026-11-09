from pathlib import Path
import json,hashlib,datetime
P=Path(__file__).resolve().parent
before=json.loads((P/'protected_before.json').read_text())
roots=[Path('/workspace')/s for s in ['test1','test3','test13','testn1','sneak_t1n']+[f'sneak_v{i}' for i in range(2,14)]+['sneak1024-seed.txt','sneak_n2']]
after={}
for root in roots:
 for f in ([root] if root.is_file() else sorted(root.rglob('*'))):
  if f.is_file() and P not in f.parents:after[str(f)]=hashlib.sha256(f.read_bytes()).hexdigest()
changed=[f for f in before if f in after and before[f]!=after[f]];added=sorted(set(after)-set(before));removed=sorted(set(before)-set(after))
lines=[datetime.datetime.now().strftime('%Y-%m-%d %I:%M:%S %p EST (America/New_York)'),f'Protected files before/after: {len(before)}/{len(after)}',f'Changed: {changed}',f'Added outside attacks_8bit/: {added}',f'Removed: {removed}']
for root in ['/workspace/sneak_n2/attacks/','/workspace/sneak_n2/baselines/']:
 items={f:h for f,h in before.items() if f.startswith(root)}
 digest=hashlib.sha256(''.join(f+' '+items[f]+'\n' for f in sorted(items)).encode()).hexdigest()
 lines.append(f'{root}: {len(items)} files unchanged; inventory SHA256 {digest}')
lines.append('PASS: all protected content and inventories byte-identical.' if not(changed or added or removed) else 'FAIL')
(P/'protected_after.json').write_text(json.dumps(after,indent=2)+'\n');(P/'protected_verification.txt').write_text('\n'.join(lines)+'\n');print('\n'.join(lines));assert not(changed or added or removed)
