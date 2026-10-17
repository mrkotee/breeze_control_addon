"""Restore production devices from existing issue #5 durable ledgers only."""
from .config import DeviceConfig
from .config_loader import DaemonConfig, RegisteredDevice
from .context import ZigbeeContext
from .counters import CounterAllocator
from .real_radio import RadioBinding
from .application_store import reserve_repeat

DEVICE_NAMES = {0: ('second_bedroom', 'AirNanny вторая спальня'),
                1: ('bedroom', 'AirNanny спальня')}
REMOTE_IEEE = {0: 0x00124b00369c711f, 1: 0x00124b0036a18944}
REMOTE_SHORT = {0: 0xc9b7, 1: 0xf59f}


class ProductionCounters:
    """The existing durable authority burns a whole block, returns one usable FC.

    V28 supports one app TX per recovery cycle. Returning only the first FC
    prevents the frozen core allocator from treating the remaining burnt block
    as 31 additional legal V28 commands. No defaults or memory-only fallback.
    """
    def __init__(self, ledgers, *, repeat_commands=False, retry_commands=False):
        self.ledgers = {f'dual-ctx{slot}': ledger for slot, ledger in ledgers.items()}
        self.repeat_commands = repeat_commands
        self.retry_commands = retry_commands

    def reserve(self, context, epoch, key_sequence, count):
        try:
            ledger = self.ledgers[context]
            block = (reserve_repeat(ledger, context, epoch, key_sequence, allow_clean_miss=self.retry_commands) if self.repeat_commands
                     else ledger.reserve_application(context, epoch, key_sequence, 32))
        except Exception:
            raise ValueError('durable_counter_reservation_failed') from None
        return range(block.start, block.start + 1)

    def intent(self, binding, tx_id, raw, fc, digest):
        ledger = self.ledgers[binding.context_id]
        r = ledger.read()
        intent = r['recovery']['intents']['TYPE07']
        if (r['generation'] != binding.generation or r['recovery']['gate'] != binding.guard
                or r['key_epoch_id'] != binding.epoch or intent['fc'] != fc):
            raise ValueError('stale durable application intent')
        ledger.application('BURNED_BEFORE_CRYPTO', phase='BUILT_NEVER_RETRY',
                           sha256=digest, host_tx_id=tx_id)
        ledger.application('BUILT_NEVER_RETRY', phase='HANDED_UNKNOWN_NO_RETRY')

    def local_complete(self, binding, tx_id, status, fields):
        ledger = self.ledgers[binding.context_id]
        intent = ledger.read()['recovery']['intents']['TYPE07']
        if intent.get('host_tx_id') != tx_id:
            raise ValueError('durable local completion identity mismatch')
        clean = (self.retry_commands and status == -2 and fields.get('cleanup') == 'safe'
                 and fields.get('reboot_required') == '0'
                 and fields.get('result') in ('no_ack', 'invalid_ack', 'cca_fail'))
        ledger.application('HANDED_UNKNOWN_NO_RETRY', phase='SENT',
                           result='local_tx_ok' if status == 0 else fields['result'] if clean else 'failed_or_unknown',
                           retry_safe=clean,
                           rf_start_us=int(fields.get('rf_start_us', '0')))

    def conclude_attempt(self, device):
        ledger = self.ledgers[device.config.context.identity]
        intent = ledger.read()['recovery']['intents']['TYPE07']
        if (intent.get('host_tx_id') != device.attempt_tx_id or intent.get('phase') != 'SENT'
                or not (intent.get('result') == 'local_tx_ok' or intent.get('retry_safe') is True)):
            raise ValueError('prior attempt is not safely completed')
        ledger.application('SENT', phase='CONCLUDED', application_result='UNCONFIRMED_BEFORE_NEW_ATTEMPT')

    def application_result(self, device):
        from .events import CommandCompleted
        ledger = self.ledgers[device.config.context.identity]
        intent = (ledger.read().get('recovery') or {}).get('intents', {}).get('TYPE07') or {}
        if intent.get('host_tx_id') != getattr(device, 'attempt_tx_id', device.tx_id) or intent.get('phase') != 'SENT':
            return
        ledger.application('SENT', phase='CONCLUDED',
                           application_result='CONFIRMED' if isinstance(device.result, CommandCompleted) else 'FAILED_OR_UNKNOWN',
                           match_revision=getattr(device.result, 'rx_revision', None))


def restore_devices(ledgers, mqtt, *, repeat_commands=False, retry_commands=False, active_slots=None):
    if set(ledgers) != {0, 1} or ledgers[0].root == ledgers[1].root:
        raise ValueError('two independent durable ledgers required')
    active_slots = frozenset((0, 1) if active_slots is None else active_slots)
    if (not active_slots or not active_slots <= {0, 1}
            or any(type(s) is not int for s in active_slots)):
        raise ValueError('nonempty explicit active context set required')
    counters = ProductionCounters({s:ledgers[s] for s in active_slots}, repeat_commands=repeat_commands, retry_commands=retry_commands)
    devices, bindings, remotes = [], [], {}
    for slot in (0, 1):
        ledger = ledgers[slot]
        r, identity = ledger.read(), ledger.identity
        q = r.get('recovery') or {}
        inactive_discovery = (slot not in active_slots and q.get('state') == 'DISCOVERING'
                              and not q.get('intents') and q.get('gate') and not q.get('leave'))
        if q.get('leave') or (q.get('state') != 'PARENT_LINK_ACTIVE' if slot in active_slots else not inactive_discovery):
            raise ValueError('durable parent link not active')
        epoch, keyseq = r['key_epoch_id'], r['keyseq']
        if (epoch != identity['epoch'] or keyseq != identity['keyseq']
                or r['context']['pan'] != identity['pan'] or r['context']['short'] != identity['short']):
            raise ValueError('durable identity mismatch')
        context_id = f'dual-ctx{slot}'
        seq = r['sequences']
        ctx = ZigbeeContext(context_id, identity['pan'], int(identity['tc_ieee'], 16), 21,
                            int(identity['raw_ieee'], 16), identity['short'], int(identity['tc_ieee'], 16),
                            active_key_sequence=keyseq, key_epochs={keyseq: epoch},
                            nwk_sequence=seq['nwk'], aps_counter=seq['aps'],
                            zcl_tsn=seq['zcl'], mac_dsn=seq['dsn'])
        ctx.keys.put(keyseq, ledger.key.value)
        ctx.incoming_high_water = {(int(source, 16), epoch, keyseq): floor - 1
                                   for source, floor in r['nwk_source_floors'].items()}
        ctx.outgoing[(epoch, keyseq)] = CounterAllocator(counters, context_id, epoch, keyseq, 32)
        name, friendly = DEVICE_NAMES[slot]
        devices.append(RegisteredDevice(DeviceConfig(name, ctx, REMOTE_SHORT[slot], f'env:DPAPI_CTX{slot}'), friendly))
        bindings.append(RadioBinding(slot, context_id, ctx.pan, ctx.local_short, ctx.local_ieee,
                                     r['generation'], epoch, identity['attempt'], q['gate'], keyseq))
        remotes[context_id] = REMOTE_IEEE[slot]
    return DaemonConfig(mqtt, tuple(devices)), tuple(bindings), counters, remotes
