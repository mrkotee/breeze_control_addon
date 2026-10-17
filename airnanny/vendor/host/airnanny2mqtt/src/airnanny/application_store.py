"""V29 repeated application intents over each existing durable context ledger.

Preserves the recovery-chain writer and every consumed FC. Only a concluded,
locally successful previous intent allows a new application reservation.
"""
import copy
from uuid import uuid4


def reserve_repeat(ledger, context, epoch, key_sequence, *, allow_clean_miss=False):
    identity = ledger.identity
    if (context, epoch, key_sequence) != (f'dual-ctx{ledger.ctx}', identity['epoch'], identity['keyseq']):
        raise ValueError('application counter context mismatch')
    record = ledger.read()
    recovery = record.get('recovery') or {}
    if (recovery.get('state') != 'PARENT_LINK_ACTIVE' or record['key_epoch_id'] != epoch
            or record['keyseq'] != key_sequence or record['context']['pan'] != identity['pan']
            or record['context']['short'] != identity['short']):
        raise ValueError('durable live context required')
    intents = recovery.setdefault('intents', {})
    previous = intents.get('TYPE07')
    if previous is not None:
        clean = (allow_clean_miss and previous.get('retry_safe') is True
                 and previous.get('result') in ('no_ack', 'invalid_ack', 'cca_fail'))
        if previous.get('phase') != 'CONCLUDED' or not (previous.get('result') == 'local_tx_ok' or clean):
            raise ValueError('prior uncertain intent is consumed; no automatic retry')
        recovery.setdefault('application_history', []).append(copy.deepcopy(previous))
    fc = record['next_fc']
    if type(fc) is not int or fc < 32 or fc + 31 > 0xfffffffe:
        raise ValueError('application FC exhausted')
    record['next_fc'] = fc + 32
    sequences = record['sequences']
    for name in ('nwk', 'aps', 'dsn', 'zcl'):
        sequences[name] = (sequences[name] + 1) & 255
    intents['TYPE07'] = dict(fc=fc, block_end=fc+31, ctx=ledger.ctx,
                             phase='BURNED_BEFORE_CRYPTO', generation=record['generation'],
                             token=uuid4().hex)
    record['recovery'] = recovery
    ledger._write(record)  # existing atomic, locked, readback-verified authority
    return range(fc, fc+32)
