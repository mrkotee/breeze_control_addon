import time,datetime

# The host's single copy of the wire version. It is verified against the
# firmware's own `wire=` field in INFO rather than trusted: the host must know
# a prefix before it can ask INFO anything, so the copy is unavoidable, and
# the check is what keeps it from drifting.
PREFIX='RADIOV10'

class Fault(RuntimeError):pass
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
class Wire:
    """One port, bounded ASCII inbox; RX processed in wire order, no lost batches."""
    def __init__(self,port,clock,records):
        self.port=port;self.clock=clock;self.records=records;self.buf=b'';self.boot=None;self.rx_revision=None
        self.id=0;self.responses=set();self.active=None;self.tx_counts={};self.on_rx=None;self.on_auto=None;self.ingress=None;self.last_session=0;self.ending=False
    def next_id(self):self.id+=1;return self.id
    def send(self,line,raw=None,kind=None):
        if not line.startswith(PREFIX+' ') or len(line)>=1024:raise Fault('COMMAND_SHAPE')
        if self.active and not (self.ending and line.split()[1] in ('END','STATUS')):raise Fault('TX_BUSY')
        fields=dict(x.split('=',1) for x in line.split() if '=' in x)
        if int(fields['id'])!=self.id or ('boot' in fields and fields['boot']!=self.boot):raise Fault('SEND_BINDING')
        if raw is not None:self.active={'id':self.id,'mac':raw.hex(),'class':kind,'accept':False,'sent_at':self.clock()}
        self.records.append({'kind':'HOST_COMMAND','utc':utc(),'monotonic':self.clock(),'raw':line})
        data=(line+'\n').encode('ascii')
        if self.port.write(data)!=len(data):raise Fault('USB_PARTIAL_WRITE')
    def read(self):
        if hasattr(self.port,'is_open') and not self.port.is_open:raise Fault('USB_DISCONNECTED')
        if b'\n' not in self.buf:
            if not self.buf:self.ingress=self.clock()
            self.buf+=self.port.read(self.port.in_waiting or 1)
        if len(self.buf)>16384:raise Fault('SERIAL_BUFFER_BOUND')
        if b'\n' not in self.buf:return None
        line,_,self.buf=self.buf.partition(b'\n')
        if len(line)>1152:raise Fault('SERIAL_LINE_BOUND')
        raw=line.rstrip(b'\r').decode('ascii');parts=raw.split()
        if len(parts)<2 or parts[0]!=PREFIX:raise Fault('UNEXPECTED_SERIAL_PROTOCOL')
        f={}
        for token in parts[2:]:
            k,v=token.split('=',1)
            if k in f:raise Fault('DUPLICATE_FIELD')
            f[k]=v
        row={'kind':parts[1],'fields':f,'raw':raw,'utc':utc(),'observed':self.ingress};self.records.append(row)
        if self.boot is None:
            if row['kind']!='INFO':raise Fault('INFO_FIRST')
            self.boot=f['boot']
        if f.get('boot')!=self.boot:raise Fault('BOOT_CHANGED')
        if f.get('rx_drop','0')!='0' or f.get('out_drop','0')!='0':raise Fault('CAPTURE_LOSS')
        if f.get('rx_cutoff_stalled','0')!='0' and not self.ending:raise Fault('RX_CUTOFF_INCOMPLETE')
        if row['kind']=='ERROR' and not self.ending:raise Fault('FIRMWARE_ERROR')
        if row['kind']=='RX':
            rev=int(f['revision'])
            if self.rx_revision is not None and rev!=self.rx_revision+1:raise Fault('RX_REVISION_GAP')
            self.rx_revision=rev
            if f.get('channel')!='21' or f.get('fcs_ok')!='1':raise Fault('RX_CONTEXT')
            if self.on_rx:self.on_rx(row)
        elif row['kind'] in ('TXACCEPT','TXDONE'):
            active=self.active
            if not active or int(f['id'])!=active['id'] or f.get('session')!='1':raise Fault('DUPLICATE_OR_UNEXPECTED_RECEIPT')
            if row['kind']=='TXACCEPT':
                if active['accept'] or f.get('mac')!=active['mac'] or f.get('class')!=active['class'] or f.get('retry')!='0':raise Fault('TX_BYTES_OR_CLASS')
                active['accept']=True;self.tx_counts[active['class']]=self.tx_counts.get(active['class'],0)+1
            else:
                if not active['accept']:raise Fault('DONE_WITHOUT_ACCEPT')
                row['completed_at']=self.clock()
                row['host_completion_latency_ms']=(self.clock()-active['sent_at'])*1000
                row['RF_ACK_timing']='time_us is the V9 radio callback timestamp; host latency is separate'
                self.active=None
        elif row['kind'] in ('AUTO_ACCEPT','AUTO_DONE'):
            if f.get('session')!='1' or not self.on_auto:raise Fault('UNEXPECTED_AUTO_POLL')
            self.on_auto(row)
        elif 'id' in f:
            receipt=(row['kind'],int(f['id']))
            if receipt in self.responses:raise Fault('DUPLICATE_FIRMWARE_RECEIPT')
            self.responses.add(receipt)
            if row['kind'] in ('INFO','STATUS'):
                new=int(f['session'])
                if new not in (0,1) or new<self.last_session:raise Fault('SESSION_CHANGED')
                self.last_session=new
        return row
    def available(self):return b'\n' in self.buf or self.port.in_waiting>0

