"""Bounded MQTT command checks for the continuous-service physical proof."""
import json
import queue
import time


def hardware_proof(loop, output, *, baseline_seconds=180, pump=None,
                   client_factory=None, clock=None, fan_target=None, slots=(0, 1)):
    """Confirm an unchanged absolute FAN target on each live context.

    Drain unrelated observer traffic during baseline waits. The legacy bounded
    proof remains unchanged; this helper belongs to the continuous-service test.
    """
    slots = tuple(slots)
    if (not slots or any(type(slot) is not int or slot not in (0, 1) for slot in slots)
            or len(set(slots)) != len(slots)):
        raise ValueError('nonempty distinct context slots 0/1 required')
    if fan_target is not None and (type(fan_target) is not int or not 1<=fan_target<=7):
        raise ValueError('explicit absolute FAN target must be 1..7')
    if client_factory is None:
        from run_radio_daemon import proof_client
        client_factory = proof_client
    clock = clock or time
    daemon, radio = loop.daemon, loop.radio
    observer, rows, faults = client_factory(daemon.config.mqtt, output)
    result = dict(status='STARTED', radio_rx_contexts=[], commands={},
                  mqtt_wire_results=[], fan_policy='preserve_current' if fan_target is None else 'explicit_absolute_target',
                  fan_target=fan_target)

    def step():
        (pump or loop.pump)()
        if radio.stopped or radio.state in ('blocked', 'disconnected'):
            raise RuntimeError('radio_session_gap_during_proof')
        if faults:
            raise RuntimeError('MQTT_observer_fault')

    def drain():
        while True:
            try:
                yield rows.get_nowait()
            except queue.Empty:
                return

    try:
        deadline = clock.monotonic() + 15
        while not (radio.connected and daemon.mqtt.connected and observer.is_connected()):
            step()
            list(drain())
            if clock.monotonic() > deadline:
                raise RuntimeError('daemon_or_observer_not_active')
            clock.sleep(.005)
        for slot in slots:
            name = ('second_bedroom', 'bedroom')[slot]
            adapter = daemon.adapters[name]
            device = adapter.device
            print(f'>>> ctx{slot}: waiting for synchronized live status; preserving FAN.', flush=True)
            deadline = clock.monotonic() + baseline_seconds
            while True:
                step()
                list(drain())
                snapshot = device.snapshot()
                if (snapshot.baseline_valid and not snapshot.baseline_pending
                        and snapshot.status_fresh and snapshot.fan is not None):
                    break
                if clock.monotonic() > deadline:
                    raise RuntimeError(f'fresh_remote_baseline_timeout:ctx{slot}')
                clock.sleep(.005)
            # Recheck after the required spacing: a stock command may have
            # changed either the settings or generation while we were pumping.
            until = clock.monotonic() + 1.6
            while clock.monotonic() < until:
                step()
                list(drain())
                clock.sleep(.005)
            snapshot = device.snapshot()
            if (not snapshot.baseline_valid or snapshot.baseline_pending
                    or not snapshot.status_fresh or snapshot.fan is None):
                raise RuntimeError(f'baseline_changed_before_command:ctx{slot}')
            target = snapshot.fan if fan_target is None else fan_target
            observer.publish(adapter.topics.command('fan'), str(target), qos=1, retain=False)
            # FAN: up to 45 s queued plus 3*20 s confirmation and 2+5 s pauses.
            deadline = clock.monotonic() + (125 if radio.firmware_version >= 32 else 25)
            wire = []
            verdict = None
            while clock.monotonic() < deadline and verdict is None:
                step()
                for topic, payload, retained in drain():
                    if topic != adapter.topics.result:
                        continue
                    item = json.loads(payload)
                    wire.append(dict(ctx=slot, retained=retained, **item))
                    if item['status'] in ('ok', 'error'):
                        verdict = item
                clock.sleep(.005)
            result['mqtt_wire_results'].extend(wire)
            if (not verdict or [row['status'] for row in wire] != ['accepted', 'ok']
                    or any(row['retained'] for row in wire)
                    or wire[0]['request_id'] != wire[1]['request_id']):
                raise RuntimeError(f'confirmed_MQTT_command_missing:ctx{slot}')
            result['commands'][str(slot)] = dict(
                requested=target, confirmation_revision=device.rx_revision,
                status='CONFIRMED', request_id=verdict['request_id'])
            if radio.firmware_version >= 32:
                result['commands'][str(slot)]['attempts'] = device._attempt
            print(f'>>> ctx{slot}: unchanged FAN confirmed by fresh TYPE06.', flush=True)
        if not all(daemon.adapters[('second_bedroom', 'bedroom')[slot]].device.status is not None
                   for slot in slots):
            raise RuntimeError('selected_status_streams_required')
        result['radio_rx_contexts'] = list(slots)
        result['status'] = 'RADIO_MQTT_COMMANDS_CONFIRMED_AWAITING_PHYSICAL_HEALTH'
    except BaseException as exc:
        result['status'] = 'FAILED_OR_UNKNOWN'
        result['reason'] = type(exc).__name__
        raise
    finally:
        output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        observer.disconnect()
        observer.loop_stop()
