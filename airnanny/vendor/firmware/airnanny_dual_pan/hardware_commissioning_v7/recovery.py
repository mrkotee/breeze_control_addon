"""One local V17 INFO after manual restoration; no RF command."""
import time
def inspect(port,clock=time.monotonic):
    port.dtr=True;command=b'airctl 20000006 info\r\n'
    if port.write(command)!=len(command):raise RuntimeError('partial_INFO_write')
    buf=b'';deadline=clock()+5
    while clock()<deadline:buf+=port.read(port.in_waiting or 1)
    response=buf.decode('ascii',errors='strict')
    rows=[]
    for line in response.splitlines():
        if line.startswith(('AIRV1 INFO ','AIRV1 DONE ')):
            fields=dict(token.split('=',1) for token in line.split()[2:] if '=' in token)
            rows.append((line.split()[1],fields))
    expected={'id':'20000006','firmware':'airnanny_status_v17_machine_serial','protocol':'1','safe_checks':'64445','safe_failed':'0','serial_checks':'3612','serial_failed':'0'}
    infos=[f for kind,f in rows if kind=='INFO'];dones=[f for kind,f in rows if kind=='DONE']
    verified=len(infos)==1 and len(dones)==1 and all(infos[0].get(k)==v for k,v in expected.items()) and dones[0]=={'id':'20000006','cmd':'info','result':'ok'}
    return {'command':command.decode().strip(),'response':response,'verified':verified,'RF_TX':0}
