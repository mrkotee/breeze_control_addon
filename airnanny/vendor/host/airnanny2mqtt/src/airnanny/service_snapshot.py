"""Read-only, allowlisted service/store summaries for an appliance's log."""
import json
from pathlib import Path

from .radio_service import EVIDENCE_CLEARABLE, OPERATOR_CLEARABLE, RECOVERABLE, REMEDIES, firmware_refusal
from .service_faults import runtime_fault_lines

MAX_JSON_BYTES = 2 * 1024 * 1024
SERVICE_STATES = {'NEW', 'RECOVERING', 'ACTIVE', 'WAITING', 'STOPPED', 'BLOCKED'}
KNOWN_REASONS = set(RECOVERABLE) | set(OPERATOR_CLEARABLE) | set(EVIDENCE_CLEARABLE) | set(REMEDIES) | {
    'service_runtime_fault', 'service_state_invalid', 'store_rollback_detected', 'radio_authenticated_leave',
    'radio_context_not_active'}
RECOVERY_STATES = {'IDLE', 'DISCOVERING', 'DISCOVERED', 'REJOIN_SENT', 'REJOINED', 'ANNOUNCE_SENT',
                   'TIMEOUT_SENT', 'PARENT_LINK_ACTIVE', 'DEGRADED_LEAVE', 'REJECTED', 'FAILED', 'STOPPED'}
PHASES = {'BURNED_BEFORE_CRYPTO', 'BUILT_NEVER_RETRY', 'SENT', 'HANDED_UNKNOWN_NO_RETRY',
          'LOCAL_OK_WAIT_REPLY', 'CONCLUDED'}
RESULTS = {'local_tx_ok', 'no_ack', 'invalid_ack', 'cca_fail', 'error', 'aborted',
           'watchdog', 'end', 'usb', 'loss', 'FAILED_OR_UNKNOWN'}
LATE_PHASES = {'BACKOFF', 'VERIFY', 'BIND', 'SCAN', 'SCAN_WAIT', 'SCAN_STATUS', 'DISCOVERY',
               'REJOIN', 'AWAIT_REJOIN', 'SHORT', 'ANNOUNCE', 'TIMEOUT', 'AWAIT_TIMEOUT',
               'ACTIVE', 'DONE', 'CHECK_STOP', 'CHECK_SCAN'}


def _object(value):
    return value if isinstance(value, dict) else {}


def _number(value):
    return value if type(value) is int and 0 <= value < 2 ** 64 else None


def _enum(value, allowed):
    if value is None:
        return None
    return value if isinstance(value, str) and value in allowed else 'unrecognized'


def _read(path):
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            return 'too_large', {}
        value = json.loads(raw)
        return ('ok', value) if isinstance(value, dict) else ('invalid', {})
    except FileNotFoundError:
        return 'missing', {}
    except (ValueError, UnicodeError):
        return 'invalid', {}
    except OSError:
        return 'unreadable', {}


def snapshot(state_path, store_paths, *, validate_store):
    """Never decrypts, reserves, writes, opens serial or accepts a secret option.

    Raw JSON is projected field by field; unknown strings and fields are not
    copied into the report. This report is evidence to inspect, not permission
    to clear a latch. The caller must run it while the bridge is stopped.
    """
    status, state = _read(state_path)
    reason = state.get('reason')
    known_reason = isinstance(reason, str) and (reason in KNOWN_REASONS or firmware_refusal(reason))
    service = dict(read_status=status, state=_enum(state.get('state'), SERVICE_STATES),
                   reason=reason if known_reason else (None if reason is None else 'unrecognized'),
                   cycles=_number(state.get('cycles')), runtime_fault=runtime_fault_lines(state))
    late = _object(state.get('late_join'))
    service['late_join'] = None if not late else dict(
        slot=late.get('slot') if type(late.get('slot')) is int and late['slot'] in (0, 1) else None,
        phase=_enum(late.get('phase'), LATE_PHASES),
        secured=late.get('secured') if type(late.get('secured')) is bool else None)
    contexts = {}
    for slot in (0, 1):
        read_status, record = _read(store_paths[slot])
        valid = None
        if read_status == 'ok':
            try:
                validate_store(slot, store_paths[slot])
                valid = True
            except Exception:
                valid = False  # A validation error may contain raw store values.
        recovery = _object(record.get('recovery'))
        intents = _object(recovery.get('intents'))
        previous = _object(_object(state.get('stores')).get(str(slot)))
        current = dict(generation=_number(record.get('generation')), next_fc=_number(record.get('next_fc')))
        baseline = {name: _number(previous.get(name)) for name in current}
        comparable = all(current[name] is not None and baseline[name] is not None for name in current)
        contexts[str(slot)] = dict(
            read_status=read_status, identity_valid=valid, **current, last_service_baseline=baseline,
            below_service_baseline=(any(current[n] < baseline[n] for n in current) if comparable else None),
            recovery_state=_enum(recovery.get('state'), RECOVERY_STATES),
            leave_present=bool(recovery.get('leave')),
            recovery_matches_service_guard=bool(state.get('guard')) and state.get('guard') == recovery.get('gate'),
            recovery_matches_late_join_guard=bool(late.get('guard')) and late.get('guard') == recovery.get('gate'),
            unknown_intents_present=any(name not in {'REJOIN', 'ANNOUNCE', 'TIMEOUT', 'TYPE07'} for name in intents),
            intents={name: dict(phase=_enum(_object(intents[name]).get('phase'), PHASES),
                                result=_enum(_object(intents[name]).get('result'), RESULTS),
                                fc=_number(_object(intents[name]).get('fc')),
                                block_end=_number(_object(intents[name]).get('block_end')))
                     for name in ('REJOIN', 'ANNOUNCE', 'TIMEOUT', 'TYPE07') if name in intents})
    return dict(kind='airnanny_service_snapshot_v1', service=service, contexts=contexts)
