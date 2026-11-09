"""Hash every protected file (excluding attacks_pickup/). Usage: snapshot_protected.py before|after"""
import sys,hashlib,json,datetime
from pathlib import Path
P=Path(__file__).resolve().parent
roots=[Path('/workspace')/s for s in ['test1','test3','test13','testn1','testn3','sneak_t1n']+[f'sneak_v{i}' for i in range(2,14)]+['sneak1024-seed.txt','sneak_n2']]
roots+=sorted(Path('/workspace').glob('*.png'))+sorted(Path('/tmp').glob('sneak_n2_*'))
cur={}
for root in roots:
 if not root.exists():continue
 for f in ([root] if root.is_file() else sorted(root.rglob('*'))):
  if f.is_file() and P not in f.parents:cur[str(f)]=hashlib.sha256(f.read_bytes()).hexdigest()
mode=sys.argv[1]
(P/f'protected_{mode}.json').write_text(json.dumps(cur,indent=2)+'\n')
if mode=='after':
 before=json.loads((P/'protected_before.json').read_text())
 changed=[f for f in before if f in cur and before[f]!=cur[f]];added=sorted(set(cur)-set(before));removed=sorted(set(before)-set(cur))
 lines=[datetime.datetime.now().strftime('%Y-%m-%d %I:%M:%S %p EST (America/New_York)'),f'Protected files before/after: {len(before)}/{len(cur)} (including existing pycache)',f'Changed: {changed}',f'Added outside attacks_pickup/: {added}',f'Removed: {removed}']
 ok=not(changed or added or removed);lines.append('PASS: all protected content byte-identical.' if ok else 'FAIL')
 (P/'protected_verification.txt').write_text('\n'.join(lines)+'\n');print('\n'.join(lines))
else:print('snapshot',len(cur),'files')
