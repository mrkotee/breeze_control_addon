"""Typed one-shot association plan; no transport and no general raw TX API."""
import struct
MAX_POLLS=2
POLL_INTERVAL_MS=500
TIMEOUT_MS=10000
def begin_command(evidence,identity,command_id):
    e=evidence;r=identity
    if e.ctx!=0 or e.pan!=0xfa9b or r['ctx']!=0 or r['state']!='ATTEMPT_RESERVED':raise ValueError('attempt context mismatch')
    if r['raw_ieee'] in r['forbidden_inventory'] or r['raw_ieee']==e.target_coordinator_ieee:raise ValueError('identity collision')
    command=(f'RADIOV3 ASSOC BEGIN_PERMIT_EVIDENCE boot={e.boot_id} id={command_id} ctx=0 raw_ieee={r["raw_ieee"]} '
             f'target_pan=fa9b extpan={e.target_coordinator_ieee} coordinator_ieee={e.target_coordinator_ieee} coordinator_short=0000 '
             f'policy={r["policy"]} attempt={r["attempt"]} permit_revision={e.rx_revision} raw_hash={e.raw_mac_hash} '
             f'validation_generation={e.validation_generation} max_polls=2 poll_interval_ms=500 timeout_ms=10000 dsn=30')
    if len(command)>=512:raise ValueError('command length exceeds immutable transport limit')
    return command
def expected_request(raw_ieee):
    return struct.pack('<HBHHH',0xc823,30,0xfa9b,0,0xffff)+bytes.fromhex(raw_ieee)[::-1]+b'\x01\x80'
def expected_poll(raw_ieee,index):
    if index not in (0,1):raise ValueError('two-poll bound')
    return struct.pack('<HBHH',0xc863,31+index,0xfa9b,0)+bytes.fromhex(raw_ieee)[::-1]+b'\x04'
def validate_response(raw,raw_ieee,coordinator,revision,request_revision):
    if len(raw)!=25 or raw[:2]!=b'\x63\xcc' or raw[3:5]!=b'\x9b\xfa' or raw[5:13]!=bytes.fromhex(raw_ieee)[::-1] or raw[13:21]!=bytes.fromhex(coordinator)[::-1] or raw[21]!=2 or revision<=request_revision or raw[24]>2:
        raise ValueError('wrong association response')
    short=int.from_bytes(raw[22:24],'little');status=raw[24]
    if status==0 and not 0<short<0xfff8:raise ValueError('invalid assigned short')
    return {'status':status,'assigned_short':short,'dsn':raw[2],'revision':revision}
