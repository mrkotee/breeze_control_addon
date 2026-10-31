import sys,unittest,subprocess,uuid,shutil,json,hashlib,copy
from pathlib import Path
from unittest.mock import patch
R=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(R/'host'))
sys.path.insert(0,str(R/'tests'))
import test_recovery as old
import ledger as lm
from ledger import Ledger,durable,load,TC,RAW,le,decode_nwk,Fault
from discovery import validate,beacon_request,SCAN_US
from probe import Probe
BOOT='1'*32;GUARD='2'*32
CRASH_WRITE_POINTS=0
class Clock:
    def __init__(self):self.now=0
    def __call__(self):return self.now
def status_plain():
    from functools import reduce
    from operator import xor
    p=bytes.fromhex('0008060004010801110201706500001106')+bytes(16)
    return p+bytes([reduce(xor,p[16:],0)])
class Port:
    """Actual V9 C dispatcher/auto scheduler; synthetic radio/USB/clock only."""
    def __init__(self,clock,mode='OK'):
        self.clock=clock;self.mode=mode;self.buf=b'';self.is_open=True;self.baseline=False;self.phase=None
        self.fc=2462300;self.short=0x6c55;self.responses=0;self.auto_count=0;self.events=[]
        self.p=subprocess.Popen([str(R/'build/firmware_cli.exe')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    def feed(self,line):
        self.p.stdin.write(line+'\n');self.p.stdin.flush();rows=[]
        while True:
            row=self.p.stdout.readline()
            if not row:raise RuntimeError('C_dispatcher_EOF')
            if row.startswith('@END'):break
            rows.append(row.strip());self.buf+=row.encode()
        for row in rows:
            if ' AUTO_ACCEPT ' in row:self.auto_count+=1;self.events.append(row)
            if ' AUTO_DONE ' in row and (('poll=1 ' in row and self.mode!='DELAYED') or ('poll=2 ' in row and self.mode=='DELAYED')):self.respond()
    def inject(self,raw):self.feed('@RX '+raw.hex())
    def respond(self):
        if self.phase=='REJOIN' and self.mode not in ('NO_REJOIN','USB','BAD_REJOIN_MIC','REPLAY_REJOIN','BAD_KEYSEQ'):
            if self.mode=='LEAVE':plain=b'\x04\x60';fcf=0x1209
            elif self.mode=='REJECT':plain=b'\x07\xff\xff\x02';fcf=0x1a09
            else:plain=b'\x07\x21\x43\0';fcf=0x1a09
            self.inject(old.vector(plain,self.fc,self.short,fcf=fcf));self.fc+=1;self.responses+=1
            if self.mode=='DUPLICATE_RESPONSE':self.inject(old.vector(plain,self.fc-1,self.short,fcf=fcf))
        elif self.phase=='REJOIN' and self.mode in ('BAD_REJOIN_MIC','REPLAY_REJOIN','BAD_KEYSEQ'):
            fc=self.fc if self.mode!='REPLAY_REJOIN' else 2462210
            raw=old.vector(b'\x07\x21\x43\0',fc,self.short,keyseq=1 if self.mode=='BAD_KEYSEQ' else 0)
            if self.mode=='BAD_REJOIN_MIC':raw=raw[:-1]+bytes([raw[-1]^1])
            self.inject(raw)
        elif self.phase=='TIMEOUT' and self.mode!='NO_TIMEOUT':
            plain=b'\x0c'+bytes([1 if self.mode=='TIMEOUT_FAIL' else 0,2 if self.mode=='BIT1' else 1])
            self.inject(old.vector(plain,self.fc,self.short));self.fc+=1;self.responses+=1
    @property
    def in_waiting(self):return len(self.buf)
    def write(self,data):
        cmd=data.decode().strip()
        if self.mode=='USB' and 'REJOIN_REQUEST' in cmd:self.is_open=False;raise OSError('synthetic_USB_disconnect')
        if 'REJOIN_REQUEST' in cmd:self.phase='REJOIN'
        if 'CURRENT_SHORT_COMMIT' in cmd:self.short=0x4321
        if 'END_DEVICE_TIMEOUT' in cmd:self.phase='TIMEOUT'
        if self.mode=='ANNOUNCE_UNKNOWN' and 'DEVICE_ANNOUNCE' in cmd:self.feed('@NOACK')
        self.feed(cmd)
        if 'ACTIVE_DISCOVERY_BEACON_REQUEST' in cmd and self.mode!='NO_BEACON':
            raw=bytearray(old.BEACON)
            if self.mode=='WRONG_PAN':raw[3]^=1
            if self.mode=='WRONG_EXTPAN':raw[14]^=1
            if self.mode=='R23':raw+=b'\x46\x01\0\0'
            if self.mode=='NO_CAPACITY':raw[13]&=0x7f
            self.inject(bytes(raw))
        return len(data)
    def read(self,n):
        if self.mode=='LATE_POLL' and self.phase=='REJOIN' and .34<=self.clock.now<.4:self.clock.now+=.08
        self.clock.now+=.001;self.feed('@TIME '+str(100000+int(self.clock.now*1e6)))
        if self.clock.now>=.01 and not self.baseline:
            self.baseline=True;self.inject(old.vector(status_plain(),self.fc,0xf59f,fcf=0x0248));self.fc+=1
        b=self.buf[:n];self.buf=self.buf[n:];return b
    def close(self):self.p.stdin.close();self.p.wait(timeout=2);self.p.stdout.close()
