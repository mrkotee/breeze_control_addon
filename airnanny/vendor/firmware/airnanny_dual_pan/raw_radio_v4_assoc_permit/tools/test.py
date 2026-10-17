"""Compile/run actual C with mock device APIs; offline only."""
from pathlib import Path
import subprocess, os, json, hashlib
R=Path(__file__).resolve().parents[1];W=R.parents[3]
zig=W/'toolchains/zig-windows-x86_64-0.13.0/zig.exe'
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(R/'build/zig-cache')
results={}
for name in ['test_assoc','test_main','test_ack_timeout','test_permit_binding']:
    sources=([R/'src'/n for n in ['assoc.c','assoc_protocol.c','assoc_filter.c','permit_binding.c']] if name!='test_ack_timeout' else [])+[R/'tests'/(name+'.c')]
    cmd=[str(zig),'cc','-std=c11','-O1','-Wall','-Wextra','-Werror']+['-I'+str(R/n) for n in ['tests','include','radio_driver']]+[str(p) for p in sources]+['-o',str(R/'build'/(name+'.exe'))]
    subprocess.run(cmd,env=env,check=True);out=subprocess.check_output([str(R/'build'/(name+'.exe'))],universal_newlines=True)
    results[name]=out.strip();print(out.strip())
    results[name+'_source_hashes']={p.relative_to(R).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
p=subprocess.run(['python',str(R/'tests/test_identity.py')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True)
print(p.stdout);p.check_returncode();results['identity_unittest']=p.stdout;results['hardware']=False
(R/'evidence/offline_test_results.json').write_text(json.dumps(results,indent=2)+'\n',encoding='utf-8')
