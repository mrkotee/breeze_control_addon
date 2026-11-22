"""Review only the diagnosed 0.21.29 MQTT subscribe exception, under owner lock."""
from .legacy_runtime_review import _review_settled_runtime_fault, _acknowledge_runtime_fault


# Exact recorded call chain of the released 0.21.29 failure. Matching only
# ConnectionError would also admit unrelated network/control exceptions.
SUBSCRIBE_FAULT_02129 = {
    'exception_type': 'ConnectionError',
    'frames': [dict(file=file, function=function, line=line) for file,function,line in (
        ('radio_service.py','pump',955),
        ('radio_service.py','pump',440),
        ('radio_daemon.py','pump',186),
        ('paho_mqtt.py','pump',169),
        ('radio_service.py','_connection',422),
        ('daemon.py','_connection',161),
        ('paho_mqtt.py','subscribe',208),
    )],
}


def _mqtt_fault_check(record):
    if (record.get('runtime_fault') != SUBSCRIBE_FAULT_02129
            or record.get('runtime_cleanup_fault') is not None):
        return 'not_diagnosed_mqtt_subscribe_fault'
    return None


def review_mqtt_runtime_fault(state, paths, *, validate_store):
    # The shared proof also checks identities, matching guards, monotonic
    # counters, only settled recovery intents, no TYPE07, no late join, and
    # unchanged files. An old trace is never considered.
    return _review_settled_runtime_fault(state, paths, validate_store=validate_store,
        fault_check=_mqtt_fault_check, success_code='mqtt_subscribe_fault_stores_settled')


def acknowledge_mqtt_runtime_fault(state, reason, paths, *, validate_store):
    return _acknowledge_runtime_fault(state, reason, paths, validate_store=validate_store,
        reviewer=review_mqtt_runtime_fault, basis='mqtt_subscribe_fault_store_review')
