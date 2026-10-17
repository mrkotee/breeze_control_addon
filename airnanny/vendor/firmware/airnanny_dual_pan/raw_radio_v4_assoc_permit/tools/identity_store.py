"""Offline durable identity/attempt allocator. No radio/serial/network dependencies.
Experimental local MAC identities are NOT a Zigbee conformance claim.
"""
from pathlib import Path
import argparse, contextlib, json, os, secrets, uuid
ROOT=Path(__file__).resolve().parents[1]
def wire(text):
    if len(text)!=16 or any(c not in '0123456789abcdef' for c in text):raise ValueError('canonical lowercase hex16 required')
    a=bytes.fromhex(text)
    if a in (bytes(8),b'\xff'*8) or a[0]&1:raise ValueError('invalid individual identity')
    return a[::-1]
@contextlib.contextmanager
def locked(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True);p=root/'owner.lock'
    fd=os.open(str(p),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        os.write(fd,str(os.getpid()).encode());os.fsync(fd);yield
    finally:os.close(fd);p.unlink()
def durable(path,value):
    # Exclusive temporary creation; replace existing record only with monotonic state.
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with temp.open('x',encoding='utf-8',newline='\n') as f:
        json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    if os.name=='nt':
        import ctypes
        move=ctypes.WinDLL('kernel32',use_last_error=True).MoveFileExW
        move.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_ulong];move.restype=ctypes.c_int
        if not move(str(temp.resolve()),str(path.resolve()),0x1|0x8):raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.replace(str(temp),str(path))
        fd=os.open(str(path.parent),os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    # Flush+write-through rename; physical disk cache/ACL guarantees require deployment review.
    return json.loads(path.read_text(encoding='utf-8'))==value
def allocate(root,ctx,forbidden,policy='local_experimental_v1',candidate=None,entropy=secrets.token_bytes):
    if ctx not in (0,1) or not forbidden:raise ValueError('ctx0/1 and explicit forbidden inventory required')
    forbidden=set(forbidden)
    for a in forbidden:wire(a)
    if policy not in ('local_experimental_v1','allocated_eui_v1'):raise ValueError('unreviewed policy')
    with locked(root):
        root=Path(root);p=root/('ctx%d.json'%ctx)
        if p.exists():
            record=json.loads(p.read_text(encoding='utf-8'));wire(record['raw_ieee'])
            if record['raw_ieee'] in forbidden or record['policy']!=policy:raise ValueError('existing identity conflict')
            for old in root.glob('ctx*.json'):
                if old!=p and json.loads(old.read_text(encoding='utf-8'))['raw_ieee']==record['raw_ieee']:raise ValueError('duplicate RAW identity in store')
            return record
        used=set(forbidden)
        for old in root.glob('ctx*.json'):used.add(json.loads(old.read_text(encoding='utf-8'))['raw_ieee'])
        for _ in range(128):
            if candidate is not None:identity=candidate
            elif policy=='allocated_eui_v1':raise ValueError('provide legitimately allocated EUI; never manufacture OUI')
            else:
                a=bytearray(entropy(8));a[0]=(a[0]&0xf0)|2;identity=bytes(a).hex()
            wire(identity);initial=int(identity[:2],16)
            if policy=='local_experimental_v1' and initial&3!=2:raise ValueError('local individual policy required')
            if policy=='allocated_eui_v1' and initial&3:raise ValueError('universal individual policy required')
            if identity not in used:break
            if candidate is not None:raise ValueError('identity collision')
        else:raise ValueError('allocation collision budget exhausted')
        record={'schema_version':1,'ctx':ctx,'raw_ieee':identity,'wire_ieee_le':wire(identity).hex(),'policy':policy,'generation':0,'attempt':None,'state':'ALLOCATED_UNUSED','hardware_used':False,'forbidden_inventory':sorted(forbidden),'durability':'file_fsync; Windows write-through rename or POSIX directory fsync; hardware cache guarantees not proved'}
        if not durable(p,record):raise OSError('durable readback mismatch')
        return record
def attempt(root,ctx,forbidden):
    if ctx not in (0,1) or not forbidden:raise ValueError('ctx and forbidden inventory required')
    for a in forbidden:wire(a)
    with locked(root):
        p=Path(root)/('ctx%d.json'%ctx);r=json.loads(p.read_text(encoding='utf-8'));wire(r['raw_ieee'])
        if r['raw_ieee'] in set(forbidden):raise ValueError('forbidden identity')
        for old in Path(root).glob('ctx*.json'):
            if old!=p and json.loads(old.read_text(encoding='utf-8'))['raw_ieee']==r['raw_ieee']:raise ValueError('duplicate RAW identity in store')
        if r['state']!='ALLOCATED_UNUSED' or r['attempt'] is not None:raise ValueError('attempt already allocated; explicit reconciliation/retirement required')
        r.update(generation=r['generation']+1,attempt=uuid.uuid4().hex,state='ATTEMPT_RESERVED')
        if not durable(p,r):raise OSError('attempt durable readback mismatch')
        return r
def save_associated(root,ctx,attempt_id,pan,coordinator,short):
    wire(coordinator)
    if not 0<=pan<0xffff or not 0<short<0xfff8:raise ValueError('association address invalid')
    with locked(root):
        p=Path(root)/('ctx%d.json'%ctx);r=json.loads(p.read_text(encoding='utf-8'))
        if r['state']!='ATTEMPT_RESERVED' or r['attempt']!=attempt_id:raise ValueError('stale association attempt')
        r.update(generation=r['generation']+1,state='ASSOCIATED_UNKEYED',target_pan=pan,coordinator_ieee=coordinator,assigned_short=short,hardware_used=True)
        if not durable(p,r):raise OSError('association durable readback mismatch')
        return r
def main():
    ap=argparse.ArgumentParser();ap.add_argument('operation',choices=['allocate','attempt','show']);ap.add_argument('--ctx',type=int,choices=[0,1],required=True);ap.add_argument('--store',type=Path,default=ROOT/'.local');ap.add_argument('--forbidden-file',type=Path,required=True);ap.add_argument('--policy',default='local_experimental_v1');ap.add_argument('--allocated-ieee')
    a=ap.parse_args();inventory=json.loads(a.forbidden_file.read_text(encoding='utf-8'))
    required=['physical_aircontrols','coordinators','v17_reference','other_raw']
    if set(inventory)!=set(required) or not inventory['v17_reference'] or not inventory['physical_aircontrols'] or not inventory['coordinators']:raise SystemExit('complete forbidden identity inventory required, including V17')
    forbidden=[x for k in required for x in inventory[k]]
    if a.operation=='allocate':r=allocate(a.store,a.ctx,forbidden,a.policy,a.allocated_ieee)
    elif a.operation=='attempt':r=attempt(a.store,a.ctx,forbidden)
    else:r=json.loads((a.store/('ctx%d.json'%a.ctx)).read_text(encoding='utf-8'))
    print(json.dumps(r,indent=2))
if __name__=='__main__':main()
