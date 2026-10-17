"""Test-only FAN checkpoint using the frozen core's captured-template mode.

Decrypt an authenticated prior transmission as DATA, never replay its secured
bytes. A new live status and newly reserved counters are still mandatory.
"""
import hashlib
import json
from pathlib import Path
from airnanny.application import Type07
from airnanny.aps import APS
from airnanny.mac import MAC
from airnanny.nwk import NWK
from airnanny.security import decrypt
from airnanny.zcl import ZCL


def install_confirmed_fan_checkpoint(root, source_run, slot, device, ledgers):
    if len(source_run) != 32 or any(c not in '0123456789abcdef' for c in source_run):
        raise ValueError('explicit local source run required')
    folder = Path(root)/'.local/v32_application_wrap'/source_run
    proof_bytes = (folder/'proof.json').read_bytes()
    proof = json.loads(proof_bytes)
    assert proof.get('context', 0) == slot and proof.get('normal_incremental_approach')
    assert proof['service_closed'] and proof['broker_stopped']
    confirmed = [c for c in proof['commands'] if c['confirmed']]
    all_confirmed = bool(confirmed) and len(confirmed) == len(proof['commands'])
    if all_confirmed:
        # An explicit stop between completed requests has no unresolved setter.
        # Verify its last durable intent against the actual secured TX below.
        assert proof.get('error_reason') == 'operator_aborted'
    else:
        assert proof['failed_command']['attempts'] == 0
        assert proof['failed_command']['actual_sequence'] is None
        assert proof['failed_command']['wire'][-1]['reason'] == 'stale_status_sequence'
    previous = json.loads((folder/'stores_after.private.json').read_text())[str(slot)]
    live_before = {i: ledger.read() for i, ledger in ledgers.items()}
    current = live_before[slot]
    assert all(previous[k] == current[k] for k in ('key_epoch_id', 'keyseq', 'secret_ref'))
    ctx = device.config.context
    assert previous['context']['pan'] == ctx.pan and previous['keyseq'] == ctx.active_key_sequence
    if all_confirmed:
        recovery = previous['recovery']
        assert recovery['state'] == 'PARENT_LINK_ACTIVE' and not recovery.get('leave')
        last_intent = recovery['intents']['TYPE07']
        assert (last_intent['phase'], last_intent['application_result']) == ('CONCLUDED', 'CONFIRMED')
    if device.baseline.valid:
        return dict(installed=False, source_run=source_run, reason='new_live_template_available')
    assert device.intent is None and device.confirmation is None
    assert len(confirmed) == len(proof['commands'])-(0 if all_confirmed else 1)
    sequences = [c['actual_sequence'] for c in confirmed]
    assert sequences and all(y == (x+1)&255 for x, y in zip(sequences, sequences[1:]))
    assert all([w['status'] for w in c['wire']] == ['accepted', 'ok']
               and all(not w['retained'] and w['command'] == 'fan' for w in c['wire']) for c in confirmed)
    rows = [json.loads(s) for s in (folder/'records.private.jsonl').read_text().splitlines()]
    assert len(rows) == proof['records']
    assert not any(r['kind'] == 'ERROR' or any(r['fields'].get(k, '0') != '0'
                   for k in ('rx_drop', 'out_drop')) for r in rows)
    done = {r['fields']['id']: r['fields'] for r in rows if r['kind'] == 'TXDONE'}
    frames = []
    secured_identities = []
    for row in rows:
        f = row['fields']
        if row['kind'] != 'TXACCEPT' or f.get('class') != 'TYPE07_FAN':
            continue
        assert f['ctx'] == str(slot) and f['boot'] == proof['boot']
        mac = MAC.parse(bytes.fromhex(f['mac']));nwk = NWK.parse(mac.payload)
        header, plain = decrypt(nwk, ctx.keys)
        assert header.source_ieee == ctx.local_ieee and header.key_sequence == ctx.active_key_sequence
        assert mac.destination_pan == mac.source_pan == ctx.pan
        assert mac.source == nwk.source == previous['context']['short']
        assert mac.destination == 0 and nwk.destination == 0xfffd and nwk.fcf == 0x2208
        aps = APS.parse(plain);zcl = ZCL.parse(aps.payload)
        assert (aps.control, aps.group, aps.cluster, aps.profile, aps.source_endpoint, zcl.control, zcl.command) == (12, 10, 6, 0x104, 8, 0x11, 1)
        frame = Type07(zcl.payload);terminal = done[f['id']]
        assert terminal['boot'] == proof['boot'] and terminal['ctx'] == str(slot)
        assert terminal['cleanup'] == 'safe' and terminal['reboot_required'] == '0'
        assert terminal['result'] in ('local_tx_ok', 'no_ack', 'invalid_ack', 'cca_fail')
        frames.append(frame)
        secured_identities.append((header.counter, hashlib.sha256(bytes.fromhex(f['mac'])).hexdigest()))
    expected = [(c['actual_sequence'], c['requested_fan']) for c in proof['commands'] for _ in range(c['attempts'])]
    assert [(f.sequence, f.fan_raw+1) for f in frames] == expected
    assert frames[-1].sequence == sequences[-1]
    if all_confirmed:
        assert (last_intent['fc'], last_intent['sha256']) == secured_identities[-1]
    device.baseline.frame = frames[-1]
    device.baseline.valid = True
    device.baseline.live = False  # Never grant POWER/NIGHT/HUMIDIFIER authority.
    device.baseline.source = None
    device.baseline.remote_pending = False
    device.baseline.generation += 1
    device._confirmed_sequences.extend(sequences[-128:])
    if device.status is not None:
        device.baseline.observe(device.status, device.rx_revision)
    assert live_before == {i: ledger.read() for i, ledger in ledgers.items()}
    return dict(installed=True, source_run=source_run, source_last_confirmed_sequence=sequences[-1],
                source_all_commands_confirmed=all_confirmed,
                template_live=False, restored_confirmed_history=len(device._confirmed_sequences),
                template_sha256=hashlib.sha256(frames[-1].raw).hexdigest(),
                source_proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
                prior_secured_bytes_replayed=False, security_stores_changed=False)
