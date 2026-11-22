"""Narrow migration out of a pre-0.21.23 runtime latch, using live stores.

The caller holds the service owner lock throughout review and acknowledgement.
No radio, key resolution, frame construction or store writer is involved.
"""
import hashlib
import json
from pathlib import Path
import re

MAX_BYTES = 2 * 1024 * 1024
REASON = 'service_runtime_fault'


def _read(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError()
    return raw, value


def _counter(value):
    return type(value) is int and 32 <= value <= 0xffffffff


def _generation(value):
    return type(value) is int and value >= 6


def _denied(code):
    return dict(permitted=False, code=code)


def review_legacy_runtime_fault(state, paths, *, validate_store):
    """Prove only the two quiescent boundaries observed in the legacy latch.

    DISCOVERING must have spent no FC at all. PARENT_LINK_ACTIVE must carry
    exactly the three successful recovery requests, whose contiguous blocks
    account for every FC since the service baseline. A TYPE07 intent, late
    join, newer recorded exception or any unmodelled condition refuses this
    migration. A different failure's recovery trace is never read.
    """
    return _review_settled_runtime_fault(state, paths, validate_store=validate_store,
        fault_check=_legacy_fault_check, success_code='legacy_runtime_stores_settled')


def _legacy_fault_check(record):
    if record.get('runtime_fault') is not None or record.get('runtime_cleanup_fault') is not None:
        return 'recorded_exception_needs_diagnosis'
    return None


def _review_settled_runtime_fault(state, paths, *, validate_store, fault_check, success_code):
    """Shared durable proof; callers must separately identify an eligible fault."""
    try:
        state_raw, record = _read(state.path)
        if (record.get('state'), record.get('reason')) != ('BLOCKED', REASON):
            return _denied('not_legacy_runtime_latch')
        refusal = fault_check(record)
        if refusal is not None:
            return _denied(refusal)
        if record.get('trace') is not None or record.get('late_join') is not None:
            return _denied('other_work_requires_review')
        guard = record.get('guard')
        if (type(record.get('version')) is not int or record['version'] != 1
                or type(record.get('cycles')) is not int or record['cycles'] < 1
                or not isinstance(guard, str) or re.fullmatch('[0-9a-f]{32}', guard) is None):
            return _denied('service_record_incomplete')
        baseline = record.get('stores')
        if not isinstance(baseline, dict) or set(baseline) != {'0', '1'} or set(paths) != {0, 1}:
            return _denied('counter_baseline_incomplete')
        evidence, raw_stores = {}, {}
        for slot in (0, 1):
            raw, store = _read(paths[slot])
            validate_store(slot, paths[slot])  # Frozen identity/key-epoch checks.
            raw_stores[slot] = raw
            previous = baseline[str(slot)]
            if (not isinstance(previous, dict)
                    or not _generation(previous.get('generation')) or not _counter(previous.get('next_fc'))
                    or not _generation(store.get('generation')) or not _counter(store.get('next_fc'))):
                return _denied('counter_values_invalid')
            if store['generation'] < previous['generation'] or store['next_fc'] < previous['next_fc']:
                return _denied('counter_rollback')
            recovery = store.get('recovery')
            if not isinstance(recovery, dict) or recovery.get('gate') != guard:
                return _denied('recovery_guard_mismatch')
            if recovery.get('leave') or recovery.get('state') == 'DEGRADED_LEAVE':
                return _denied('authenticated_leave')
            intents = recovery.get('intents')
            if not isinstance(intents, dict):
                return _denied('intent_record_invalid')
            if recovery.get('state') == 'DISCOVERING':
                if (intents or store['next_fc'] != previous['next_fc']
                        or store['generation'] != previous['generation']):
                    return _denied('discovery_spent_or_changed_state')
                boundary = 'discovery_spent_nothing'
            elif recovery.get('state') == 'PARENT_LINK_ACTIVE':
                if set(intents) != {'REJOIN', 'ANNOUNCE', 'TIMEOUT'}:
                    return _denied('application_or_unknown_intent')
                next_fc = previous['next_fc']
                for name in ('REJOIN', 'ANNOUNCE', 'TIMEOUT'):
                    intent = intents[name]
                    if (not isinstance(intent, dict) or intent.get('phase') != 'SENT'
                            or intent.get('result') != 'local_tx_ok'
                            or type(intent.get('ctx')) is not int or intent['ctx'] != slot
                            or not _counter(intent.get('fc')) or intent['fc'] != next_fc
                            or type(intent.get('block_end')) is not int
                            or intent['block_end'] != next_fc + 31):
                        return _denied('recovery_chain_not_settled')
                    next_fc += 32
                if next_fc != store['next_fc']:
                    return _denied('unaccounted_counter_reservation')
                boundary = 'successful_recovery_no_application_intent'
            else:
                return _denied('unmodelled_recovery_boundary')
            evidence[str(slot)] = dict(boundary=boundary, generation=store['generation'],
                                       next_fc=store['next_fc'], sha256=hashlib.sha256(raw).hexdigest())
        # Validate from disk again before offering permission, even though
        # cooperating processes are already excluded by the owner's lock.
        if state.path.read_bytes() != state_raw or any(Path(paths[s]).read_bytes() != raw_stores[s] for s in (0, 1)):
            return _denied('records_changed_during_review')
        return dict(permitted=True, code=success_code,
                    state_sha256=hashlib.sha256(state_raw).hexdigest(), stores=evidence)
    except Exception:
        # Store validators may include raw values in their error messages.
        return _denied('store_or_state_validation_failed')


def acknowledge_legacy_runtime_fault(state, reason, paths, *, validate_store):
    """Recheck current files at the point of the explicit acknowledgement."""
    return _acknowledge_runtime_fault(state, reason, paths, validate_store=validate_store,
        reviewer=review_legacy_runtime_fault, basis='legacy_runtime_store_review')


def _acknowledge_runtime_fault(state, reason, paths, *, validate_store, reviewer, basis):
    record = state.read()
    if record['state'] != 'BLOCKED':
        return 'not_blocked'
    if reason != REASON or record.get('reason') != reason:
        return 'mismatch'
    if state.acknowledgement_spent(reason):
        return 'not_clearable'
    review = reviewer(state, paths, validate_store=validate_store)
    if not review['permitted']:
        return 'not_clearable'
    cleared = dict(record.get('cleared') or {})
    previous_count = cleared.get(reason, 0)
    if type(previous_count) is not int or previous_count < 0:
        return 'not_clearable'
    cleared[reason] = previous_count + 1
    state.write('WAITING', reason=None, cleared=cleared,
                consumed_acknowledgement={'reason': reason, 'cycles': record['cycles']},
                last_cleared={'reason': reason, 'basis': basis, 'review': review})
    return 'cleared'
