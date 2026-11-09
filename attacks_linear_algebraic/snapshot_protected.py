"""Hash every protected file (excluding attacks_linear_algebraic/). Usage: snapshot_protected.py before|after"""
import sys,hashlib,json,datetime
sys.dont_write_bytecode=True
from pathlib import Path
from zoneinfo import ZoneInfo
P=Path(__file__).resolve().parent
assert hashlib.sha256((P.parent/'sneak_n2.py').read_bytes()).hexdigest()=='0eb6052f7ef1e48a952c5530983acead5932be469693134b65f2b21aaf5092c1'
roots=[Path('/workspace')/s for s in ['test1','test3','test13','testn1','testn3','testn4','sneak_t1n']+[f'sneak_v{i}' for i in range(2,14)]+['sneak1024-seed.txt','sneak_n2']]
roots+=sorted(Path('/workspace').glob('*.png'))+sorted(Path('/tmp').glob('sneak_n2_*'))
cur={}
for root in roots:
 if not root.exists():continue
 for f in ([root] if root.is_file() else sorted(root.rglob('*'))):
  if f.is_file() and P not in f.parents and f!=P:cur[str(f)]=hashlib.sha256(f.read_bytes()).hexdigest()
mode=sys.argv[1]
(P/f'protected_{mode}.json').write_text(json.dumps(cur,indent=2)+'\n')
ts=datetime.datetime.now(ZoneInfo('America/New_York')).strftime('%Y-%m-%d %I:%M:%S %p %Z (America/New_York)')
if mode=='after':
 before=json.loads((P/'protected_before.json').read_text())
 changed=[f for f in before if f in cur and before[f]!=cur[f]];added=sorted(set(cur)-set(before));removed=sorted(set(before)-set(cur))
 lines=[ts,f'Protected files before/after: {len(before)}/{len(cur)}',f'Changed: {changed}',f'Added outside attacks_linear_algebraic/: {added}',f'Removed: {removed}',
  'live sneak_n2.py sha256: '+cur.get('/workspace/sneak_n2/sneak_n2.py','MISSING')]
 ok=not(changed or added or removed);lines.append('PASS: all protected content byte-identical.' if ok else 'FAIL')
 (P/'protected_verification.txt').write_text('\n'.join(lines)+'\n');print('\n'.join(lines))
else:print(ts,'snapshot',len(cur),'files; live sha',cur.get('/workspace/sneak_n2/sneak_n2.py'))
