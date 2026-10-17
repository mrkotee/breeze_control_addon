import re
from application_control import ApplicationProbe,FirstFanControl
from ledger import Fault,TC,EPOCH,ATTEMPT

class HardwareProbe(ApplicationProbe):
    def command(self,verb,fields='',raw=None):
        if verb=='BIND' and (not getattr(self,'permit_observed_host',None) or not 0<=self.clock()-self.permit_observed_host<30):raise Fault('fresh_observed_pairing_required_before_BIND')
        result=super().command(verb,fields,raw)
        if verb=='INFO':
            if not re.fullmatch('[0-9a-f]{32}',result.get('boot','')):raise Fault('fresh_boot_UUID_required')
            if any(result.get(k)!=v for k,v in dict(identity='airnanny_ctx1_rx_admission_v25',tx_power_dbm='8',version='25',max_run_seconds='360',max_total_polls='400',max_discovery_scans='3',session='0',pending_tx='0',rx_drop='0',out_drop='0').items()):
                raise Fault('pristine_V22_required')
            self.w.rx_revision=int(result['rx_revision'])
            status=super().command('STATUS','session=0')
            if any(status.get(k)!=v for k,v in dict(state='IDLE',recovery='IDLE',session='0',pending='0',immediate_ack='0',tx_owner='free',quarantine='0',reboot_required='0',accepted_count='0',terminal_count='0',rx_drop='0',out_drop='0').items()):
                raise Fault('pristine_V22_lifecycle_required')
            self.await_pairing(status)
        return result

    def on_rx(self,row):
        observer=getattr(self,'permit_observer',None)
        if getattr(self,'waiting_pairing',False) and observer:
            evidence=observer.receive(bytes.fromhex(row['fields']['mac']),row['fields'],self.ledger.key)
            if evidence:
                from dataclasses import asdict
                self.permit_observed_host=self.clock();self.ledger.baseline=None
                self.records.append(dict(kind='PAIRING_PERMIT',fields=asdict(evidence),observed=self.permit_observed_host))
                print('PAIRING_PERMIT_OBSERVED: authenticated A7 permit; continuing discovery',flush=True)
        super().on_rx(row)

    def await_pairing(self,status):
        from permit_observation import PermitObservation
        self.permit_observer=PermitObservation(self.w.boot,self.w.rx_revision,int(status['time_us']),
            self.ledger.read()['nwk_source_floors'].get(TC,0))
        self.waiting_pairing=True;self.permit_observed_host=None
        print('PAIRING_WAIT: hold only bedroom A7 power about 15s until blinking, then release yourself; 60s window',flush=True)
        end=self.clock()+60
        try:
            while self.clock()<end and self.permit_observer.evidence is None:self.w.read()
        finally:self.waiting_pairing=False
        if self.permit_observer.evidence is None:raise Fault('no_fresh_authenticated_pairing_permit_NO_TX')

    def application_ready(self):
        # Same frozen adapter/preflight/confirmation; bounded operator baseline
        # window expanded to 25s within firmware's original 120s session limit.
        self.ledger.app=FirstFanControl(self.ledger,self.w.boot,self.session,self.clock())
        app=self.ledger.app
        print('LIVE_READY: original bedroom AirControl FAN baseline needed now; 25 seconds',flush=True)
        end=self.clock()+25
        while self.clock()<end and (app.status is None or not app.baseline.valid or app.baseline.remote_pending):
            self.keepalive();self.w.read()
        floor=self.command('STATUS','session=1')
        if floor.get('recovery')!='PARENT_LINK_ACTIVE' or floor.get('pending')!='0' or floor.get('generation')!=str(self.ledger.read()['generation']):
            raise Fault('current_live_STATUS_required')
        app.command_radio_floor=int(floor['time_us'])
        raw=app.prepare(self.clock());r=self.ledger.read();i=r['application_intent']
        app.handoff(self.clock())
        fields=(f'session=1 generation={r["generation"]} epoch={EPOCH} attempt={ATTEMPT} guard={self.ledger.guard} '
                f'fc={i["fc"]} hash={i["sha256"]} mac={raw.hex()}')
        receipt=self.command('TYPE07_FAN',fields,raw)
        app.complete(0 if receipt['result']=='local_tx_ok' else -1,self.clock(),int(receipt['rf_start_us']))
        while app.result is None:self.keepalive();self.w.read();app.tick(self.clock())
        if app.result!='CONFIRMED':raise Fault('application_confirmation_failed_or_unknown')
