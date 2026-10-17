"""Offline captured legacy MAC and commissioning security subset. No I/O/radio."""
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

@dataclass
class Mac:
    fcf:int
    dsn:int
    dst_pan:bytes
    dst:bytes
    src_pan:bytes
    src:bytes
    payload:bytes
    @classmethod
    def parse(cls,raw):
        if len(raw)<3:raise ValueError('short MAC')
        f=int.from_bytes(raw[:2],'little');i=3
        if f&0x3308:raise ValueError('unsupported version/security/sequence suppression/IE')
        dm=(f>>10)&3;sm=(f>>14)&3
        if dm==1 or sm==1:raise ValueError('reserved addressing mode')
        def take(n):
            nonlocal i
            if i+n>len(raw):raise ValueError('truncated MAC')
            v=raw[i:i+n];i+=n;return v
        dp=take(2) if dm else b'';d=take({0:0,2:2,3:8}[dm])
        sp=take(2) if sm and not f&0x40 else b'';s=take({0:0,2:2,3:8}[sm])
        return cls(f,raw[2],dp,d,sp,s,raw[i:])
    def serialize(self):
        return self.fcf.to_bytes(2,'little')+bytes([self.dsn])+self.dst_pan+self.dst+self.src_pan+self.src+self.payload
    def association(self):
        if self.fcf&7!=3:raise ValueError('not MAC command')
        if len(self.payload)==2 and self.payload[0]==1:return {'command':1,'capability':self.payload[1]}
        if len(self.payload)==4 and self.payload[0]==2:return {'command':2,'assigned_short':int.from_bytes(self.payload[1:3],'little'),'status':self.payload[3]}
        raise ValueError('not association')

def xor(a,b):return bytes(x^y for x,y in zip(a,b))
def mmo(data):
    if len(data)>=8192:raise ValueError('hash input out of supported subset')
    padded=data+b'\x80'
    padded+=b'\0'*((14-len(padded))%16)+(len(data)*8).to_bytes(2,'big')
    h=bytes(16)
    for i in range(0,len(padded),16):
        block=padded[i:i+16];e=Cipher(algorithms.AES(h),modes.ECB()).encryptor()
        h=xor(e.update(block)+e.finalize(),block)
    return h
def key_hash(key,selector):
    if len(key)!=16 or selector not in (0,2,3):raise ValueError('unsupported key derivation')
    return mmo(xor(key,b'\x5c'*16)+mmo(xor(key,b'\x36'*16)+bytes([selector])))
def secured_decode(header,secured,key,controls):
    if not secured or secured[0] not in controls:raise ValueError('unsupported security control')
    wire=secured[0];length=14 if wire==0x28 else 13
    if len(secured)<length+4:raise ValueError('truncated secured payload')
    aux=secured[:length];effective=bytes([(wire&~7)|5])+aux[1:]
    nonce=aux[5:13]+aux[1:5]+effective[:1];aad=header+effective
    plain=AESCCM(key,tag_length=4).decrypt(nonce,secured[length:],aad)
    assert AESCCM(key,tag_length=4).encrypt(nonce,plain,aad)==secured[length:]
    return plain,{'wire_control':wire,'effective_control':effective[0],'counter':int.from_bytes(aux[1:5],'little'),'source_ieee':aux[5:13][::-1].hex(),'keyseq':aux[13] if length==14 else None,'nonce':nonce.hex(),'aad':aad.hex(),'reencrypt_exact':True}
def transport_decode(aps,tc_key):
    if len(aps)<19 or aps[0]!=0x21 or aps[2] not in (0x30,0x38):raise ValueError('unsupported Transport Key envelope')
    selector=0 if aps[2]==0x30 else 2
    p,meta=secured_decode(aps[:2],aps[2:],key_hash(tc_key,selector),(aps[2],))
    if len(p) not in (34,35) or p[0]!=5:raise ValueError('unexpected Transport Key command')
    # Key remains in memory; caller must never log plaintext/repr.
    key=p[2:18]
    if p[1]==1 and len(p)==35:seq=p[18];dst=p[19:27];src=p[27:35]
    elif p[1]==4 and len(p)==34:seq=None;dst=p[18:26];src=p[26:34]
    else:raise ValueError('unsupported transported key type')
    meta.update(command=5,delivered_key_type=p[1],delivered_key_sequence=seq,destination_ieee=dst[::-1].hex(),trust_center_ieee=src[::-1].hex(),derivation_selector=selector,plaintext_length=len(p))
    return key,meta

def association_request(pan,coordinator_short,ieee_le,dsn):
    if len(ieee_le)!=8 or not 0<=dsn<=255 or not 0<=pan<0xffff or not 0<=coordinator_short<0xfff8:raise ValueError('invalid association inputs')
    return Mac(0xc823,dsn,pan.to_bytes(2,'little'),coordinator_short.to_bytes(2,'little'),b'\xff\xff',ieee_le,b'\x01\x80')
def association_response(pan,device_ieee_le,coordinator_ieee_le,dsn,short,status):
    if len(device_ieee_le)!=8 or len(coordinator_ieee_le)!=8 or not 0<=dsn<=255 or not 0<=pan<0xffff or not 0<=short<=0xffff or status not in (0,1,2):raise ValueError('invalid response inputs')
    if status==0 and short>=0xfff8:raise ValueError('invalid success short')
    return Mac(0xcc63,dsn,pan.to_bytes(2,'little'),device_ieee_le,b'',coordinator_ieee_le,b'\x02'+short.to_bytes(2,'little')+bytes([status]))
