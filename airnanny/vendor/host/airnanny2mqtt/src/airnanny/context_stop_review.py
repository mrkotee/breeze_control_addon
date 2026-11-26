"""Explicit restart review for an old radio_context_not_active latch.

The old transport discarded the failing STATUS fields. This does not infer
them: it proves only a quiescent durable boundary permitting a new boot and
fresh recovery, with all consumed counters preserved and no command replay.
"""
import re
from .legacy_runtime_review import _review_settled_runtime_fault, _acknowledge_runtime_fault

REASON='radio_context_not_active'


def _fault_check(record):
    if record.get('runtime_fault') is not None or record.get('runtime_cleanup_fault') is not None:
        return 'other_exception_requires_review'
    return None


def _applications(slot,store,next_fc):
    recovery=store['recovery']
    history=recovery.get('application_history',[])
    current=recovery['intents'].get('TYPE07')
    if not isinstance(history,list) or len(history)>10000 or (history and current is None):
        raise ValueError('application history incomplete')
    applications=history+([current] if current is not None else [])
    for index,intent in enumerate(applications):
        if (not isinstance(intent,dict) or type(intent.get('ctx')) is not int or intent['ctx']!=slot
                or type(intent.get('generation')) is not int or intent['generation']!=store['generation']
                or type(intent.get('fc')) is not int or intent['fc']!=next_fc
                or type(intent.get('block_end')) is not int or intent['block_end']!=next_fc+31
                or not isinstance(intent.get('token'),str)
                or re.fullmatch('[0-9a-f]{32}',intent['token']) is None):
            raise ValueError('application binding or block invalid')
        if intent.get('phase')=='BURNED_BEFORE_CRYPTO':
            if (index!=len(applications)-1 or intent is not current
                    or set(intent)!={'ctx','generation','fc','block_end','token','phase'}):
                raise ValueError('not a pristine unused final reservation')
        elif intent.get('phase')=='CONCLUDED':
            clean=(intent.get('retry_safe') is True and intent.get('result') in ('no_ack','invalid_ack','cca_fail'))
            if intent.get('result')!='local_tx_ok' and not clean:
                raise ValueError('application outcome not settled')
        else:
            raise ValueError('application still uncertain')
        next_fc+=32
    return next_fc


def review_context_stop(state,paths,*,validate_store):
    return _review_settled_runtime_fault(state,paths,validate_store=validate_store,
        fault_check=_fault_check,success_code='context_stop_stores_settled',
        expected_reason=REASON,application_check=_applications)


def acknowledge_context_stop(state,reason,paths,*,validate_store):
    return _acknowledge_runtime_fault(state,reason,paths,validate_store=validate_store,
        reviewer=review_context_stop,basis='context_stop_store_review',expected_reason=REASON)
