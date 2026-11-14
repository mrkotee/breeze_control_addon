"""A refused startup commit permits a fresh cycle only with full TX proof."""
from .radio_service import RECOVERY_FRAMES, sent_frame_proven

COMMANDS = frozenset(('INFO', 'STATUS', 'STATS', 'BIND', 'ACTIVE_DISCOVERY_BEACON_REQUEST',
                      'DISCOVERY_COMMIT', 'CURRENT_SHORT_COMMIT', 'REJOIN_REQUEST',
                      'DEVICE_ANNOUNCE', 'END_DEVICE_TIMEOUT', 'PARENT_LINK_ACTIVE', 'MANAGEMENT_POLL'))
CLASSES = frozenset(('ACTIVE_DISCOVERY_BEACON_REQUEST', 'REJOIN_REQUEST', 'DEVICE_ANNOUNCE',
                     'END_DEVICE_TIMEOUT', 'MANAGEMENT_POLL'))
CLEAN_RESULTS = frozenset(('local_tx_ok', 'no_ack', 'invalid_ack', 'cca_fail'))


def _command(raw):
    tokens = raw.split()
    if len(tokens) < 3 or tokens[0] != 'RADIOV10' or tokens[1] not in COMMANDS:
        return None
    fields = {}
    for token in tokens[2:]:
        key, sep, value = token.partition('=')
        if not sep or key in fields:
            return None
        fields[key] = value
    if not fields.get('id', '').isdigit():
        return None
    return tokens[1], fields


def control_refusal_retry_safe(error, ledgers, guard, records):
    """Retry a NEW cycle, never replay the refused commit or a secured frame.

    Only control_state for PARENT_LINK_ACTIVE is modelled. Every accepted
    transmission must have its own unique safe completion; every secured
    frame must also match a spent, successful durable intent under this
    cycle's guard. A different ERROR, application command, missing record,
    captured loss or uncertain outcome still requires review.
    """
    try:
        return _proven(error, ledgers, guard, records)
    except (KeyError, TypeError, ValueError, AttributeError, OSError):
        return False


def _proven(error, ledgers, guard, records):
    if str(error) != 'FIRMWARE_ERROR' or not records or len(records) >= 4096 or set(ledgers) != {0, 1}:
        return False
    if not isinstance(guard, str) or len(guard) != 32 or any(c not in '0123456789abcdef' for c in guard):
        return False
    commands = {}
    order = []
    for row in records:
        fields = row.get('fields') or {}
        if any(fields.get(name, '0') != '0' for name in ('rx_drop', 'out_drop', 'quarantine', 'reboot_required')):
            return False
        if row.get('kind') == 'HOST_COMMAND':
            parsed = _command(row.get('raw', ''))
            if parsed is None or parsed[1]['id'] in commands:
                return False
            commands[parsed[1]['id']] = parsed
            order.append(parsed[1]['id'])
    # Command one is written before the first read. Its presence proves the
    # oldest part of this FIFO transcript was not evicted.
    if not order or order[0] != '1' or commands['1'][0] != 'INFO':
        return False
    errors = [r['fields'] for r in records if r.get('kind') == 'ERROR']
    if len(errors) != 1 or errors[0].get('reason') != 'control_state':
        return False
    refused = errors[0]
    identifier = refused.get('id')
    if identifier not in commands or identifier != order[-1]:
        return False
    verb, command = commands[identifier]
    if verb != 'PARENT_LINK_ACTIVE' or command.get('ctx') not in ('0', '1') or command.get('session') != '1':
        return False
    if not command.get('boot') or refused.get('boot') != command['boot']:
        return False
    named = int(command['ctx'])

    accepted, completed = {}, set()
    for row in records:
        kind, fields = row.get('kind'), row.get('fields') or {}
        if kind not in ('TXACCEPT', 'TXDONE', 'AUTO_ACCEPT', 'AUTO_DONE'):
            continue
        if (fields.get('ctx') not in ('0', '1') or fields.get('session') != '1'
                or fields.get('boot') != command['boot'] or not fields.get('id', '').isdigit()):
            return False
        auto = kind.startswith('AUTO')
        if auto and not fields.get('poll', '').isdigit():
            return False
        key = (auto, fields['ctx'], fields.get('id'), fields.get('poll') if auto else None)
        if kind in ('TXACCEPT', 'AUTO_ACCEPT'):
            if (key in accepted or fields.get('class') not in CLASSES
                    or (auto and fields.get('class') != 'MANAGEMENT_POLL')
                    or (not auto and fields.get('id') == identifier)):
                return False
            request = commands.get(fields['id'])
            if request is None or request[1].get('ctx') != fields['ctx']:
                return False
            if (request[1].get('session') != '1'
                    or (not auto and request[0] != fields['class'])
                    or (auto and request[0] not in ('REJOIN_REQUEST', 'END_DEVICE_TIMEOUT'))):
                return False
            accepted[key] = fields
        else:
            if (key not in accepted or key in completed or fields.get('cleanup') != 'safe'
                    or fields.get('reboot_required') != '0' or fields.get('result') not in CLEAN_RESULTS):
                return False
            completed.add(key)
    if set(accepted) != completed:
        return False
    for request_id, (request_verb, request_fields) in commands.items():
        if request_verb in CLASSES:
            # A request with neither ACCEPT nor DONE is an unknown outcome,
            # not proof that the dongle transmitted nothing.
            if (False, request_fields.get('ctx'), request_id, None) not in accepted:
                return False

    secured = {(int(f['ctx']), f['class']) for f in accepted.values()
               if f['class'] in {v[0] for v in RECOVERY_FRAMES.values()}}
    expected = set()
    for slot, ledger in ledgers.items():
        record = ledger.read()
        recovery = record.get('recovery') or {}
        if recovery.get('leave') or recovery.get('state') == 'DEGRADED_LEAVE':
            return False
        if recovery.get('gate') != guard:
            if slot == named or any(int(f['ctx']) == slot for f in accepted.values()):
                return False
            continue
        intents = recovery.get('intents') or {}
        if slot != named and recovery.get('state') == 'DISCOVERING' and not intents:
            if any(ctx == slot for ctx, _ in secured):
                return False
            continue
        if (recovery.get('state') != 'PARENT_LINK_ACTIVE'
                or set(intents) != {'REJOIN', 'ANNOUNCE', 'TIMEOUT'}):
            return False
        if slot == named and command.get('generation') != str(record['generation']):
            return False
        for name, intent in intents.items():
            if type(intent.get('ctx')) is not int or intent['ctx'] != slot:
                return False
            if not sent_frame_proven(records, record, slot, name, intent):
                return False
            expected.add((slot, RECOVERY_FRAMES[name][0]))
    return secured == expected
