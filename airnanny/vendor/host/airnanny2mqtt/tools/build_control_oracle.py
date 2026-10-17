"""Compile original V17 pure functions and save independent command/trace expectations."""
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "src"))
from airnanny.application import checksum

KINDS = ("fan", "mode", "temp", "humidifier", "night", "power")


def main():
    cache = ROOT / ".tmp/control-oracle"
    cache.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(cache / "global"), ZIG_LOCAL_CACHE_DIR=str(cache / "local"),
               TEMP=str(cache), TMP=str(cache))
    zig = REPO.parent / "toolchains/zig-windows-x86_64-0.13.0/zig.exe"
    exe = cache / "oracle.exe"
    subprocess.run([str(zig), "cc", "-O2", "-I", str(REPO / "firmware/airnanny_v17"),
                    str(ROOT / "tools/control_oracle.c"), "-o", str(exe)], env=env, check=True)
    # Seed from V17 air_fan_init; modify proven fields like its pure selftest fixtures.
    base_seed = bytes.fromhex("706500000f074cfa00f500020000081a020b592521")
    rng = random.Random(17017)
    cases = []
    commands = [("fan", n) for n in range(1,8)] + [("mode", n) for n in range(3)] + [
        ("temp", n) for n in list(range(100,301,5))+[-1000]] + [("humidifier", n) for n in range(3)] + [
        ("night", n) for n in range(2)] + [("power", n) for n in range(2)]
    for kind, value in commands:
        for variant in range(4):
            b = bytearray(base_seed)
            for offset in (9,10,14,15,16,17,18): b[offset] = rng.randrange(256)
            b[6]=rng.randrange(256); b[7:9]=(200).to_bytes(2,"little"); b[11]=rng.randrange(7)
            b[12]=0; b[13]=0; b[19]=(rng.randrange(256)&~0x11)|1
            if kind=="power": b[19]=(b[19]&~1)|(1-value)
            b=checksum(b)
            s=bytearray.fromhex("706500001106ff00008f00b500c80002002a0003050564")
            s[6]=[0,0xfe,0xff,97][variant];s[13:15]=b[7:9];s[15]=b[11];s[16]=b[12];s[18]=b[13];s[21]=b[19]&0x11
            s=checksum(s)
            begin=f"BEGIN {KINDS.index(kind)} {value&65535} 100 1 1 51639 1 0 {b.hex()} {s.hex()}"
            output=json.loads(subprocess.check_output([str(exe)],input=begin+"\n",text=True))
            cases.append(dict(kind=kind,value=value,baseline=b.hex(),status=s.hex(),expected=output))
    traces=[]
    for kind in KINDS:
        case=next(c for c in cases if c['kind']==kind and c['value']==dict(fan=5,mode=1,temp=205,humidifier=1,night=1,power=0)[kind])
        for scenario in ("success","before_callback","wrong_seq","wrong_state","interruption","local_failure","generation","stale_callback"):
            tx=bytes.fromhex(case['expected']['tx']); good=bytearray.fromhex(case['status'])
            good[6]=tx[6];good[13:15]=tx[7:9];good[15]=0 if kind=='night' else tx[11]
            good[16]=tx[12];good[18]=tx[13];good[21]=tx[19]&0x11;good=checksum(good)
            begin=f"BEGIN {KINDS.index(kind)} {case['value']&65535} 100 1 1 51639 1 0 {case['baseline']} {case['status']}"
            ops=[]
            if scenario not in ('before_callback','stale_callback'):
                ops.append(['COMPLETE',101,1,-1 if scenario=='local_failure' else 0])
            raw=bytearray(good)
            if scenario=='wrong_seq':raw[6]=(raw[6]+2)&255
            if scenario=='wrong_state':raw[15]=(raw[15]+1)%7
            gen=2 if scenario=='generation' else 1
            ops.append(['RX',102,gen,checksum(raw).hex()])
            if scenario=='interruption':
                raw[6]=(raw[6]+2)&255;ops.append(['RX',1100,1,checksum(raw).hex()])
            if scenario in ('before_callback','stale_callback'):
                ops.append(['COMPLETE',103 if scenario=='before_callback' else 15103,1,0])
            ops.append(['RX',17000 if scenario=='stale_callback' else 1200,gen,checksum(raw).hex()])
            lines=[begin]+[' '.join(map(str,op)) for op in ops]
            expected=[json.loads(line) for line in subprocess.check_output([str(exe)],input='\n'.join(lines)+'\n',text=True).splitlines()]
            traces.append(dict(kind=kind,case=cases.index(case),scenario=scenario,operations=ops,expected=expected))
    paths=list((REPO/'firmware/airnanny_v17').glob('airnanny_*.h'))+[REPO/'firmware/airnanny_v17/main_airnanny_min.c']
    output=dict(provenance="Compiled unchanged V17 headers with Zig 0.13.0 cc; synthetic non-secret fields based on air_fan_init and V17 selftests",
                sources={str(p.relative_to(REPO)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                builders=cases,traces=traces)
    (ROOT/'fixtures/control_oracle.json').write_text(json.dumps(output,indent=2)+'\n')
    print(f"V17 oracle: {len(cases)} builders, {len(traces)} traces")


if __name__=='__main__':main()
