"""Bounded stock-template handoff from the current owned recovery transcript.

Old TYPE06 packets never enter application state: the new runtime must receive
its own fresh status before a handed-off template can authorize a command.
"""
import math
from .aps import APS
from .mac import MAC
from .nwk import NWK
from .security import decrypt
from .zcl import ZCL
from .application import Type07


def handoff_recovery_stock(ingress, records, *, boot, now, active_contexts):
    """Use only same-boot, recently observed RX; normal ingress owns all writes.

    The caller supplies the in-memory transcript of its validated recovery,
    before any application RX or command. This is not a saved-capture loader.
    Templates are bounded to the recovery's 90-second tail; status freshness
    is independently enforced by the frozen core on subsequent live TYPE06.
    """
    if (not isinstance(boot, str) or len(boot) != 32
            or any(c not in '0123456789abcdef' for c in boot)
            or type(now) not in (int, float) or not math.isfinite(now)):
        raise ValueError('owned recovery clock and boot required')
    devices = ingress.daemon.collection.by_context
    active = set(active_contexts)
    if not active or not active <= devices.keys():
        raise ValueError('owned active contexts required')
    if any(d.status is not None or d.baseline.frame is not None
           or d.intent is not None or d.confirmation is not None
           for d in devices.values()):
        raise ValueError('handoff requires untouched application state')
    pans = {devices[c].config.context.pan: c for c in active}
    if len(pans) != len(active):
        raise ValueError('unique active PANs required')
    result = dict(considered=0, candidates=0, admitted_stock_commands=0)
    # Wire already validated capture continuity, CRC/channel and this boot.
    # Recheck provenance here and bound memory/work, without replaying statuses.
    for row in records[-4096:]:
        if row.get('kind') != 'RX':
            continue
        f = row.get('fields', {})
        observed = row.get('observed')
        if (f.get('boot') != boot or f.get('channel') != '21'
                or f.get('fcs_ok') != '1' or type(observed) not in (int, float)
                or not math.isfinite(observed) or not 0 <= now-observed <= 90):
            continue
        result['considered'] += 1
        try:
            raw = bytes.fromhex(f['mac'])
            mac = MAC.parse(raw)
            context_id = pans.get(mac.destination_pan)
            if context_id is None:
                continue
            ctx = devices[context_id].config.context
            nwk = NWK.parse(mac.payload)
            header, plain = decrypt(nwk, ctx.keys)
            if header.key_sequence != ctx.active_key_sequence:
                continue
            aps = APS.parse(plain)
            zcl = ZCL.parse(aps.payload)
            if (aps.cluster, aps.profile, aps.source_endpoint, zcl.control) != (6, 0x104, 8, 0x11):
                continue
            if zcl.command == 1:
                Type07(zcl.payload)  # excludes every historical TYPE06
            elif not (zcl.command == 2 and not zcl.payload
                      and header.source_ieee == ingress.remote_ieees[context_id]):
                continue
        except (ValueError, KeyError):
            continue
        # Authentication above is a prefilter only: normal ingress validates
        # the full pinned envelope and consumes the durable floor BEFORE any
        # baseline/address mutation. Never swallow a durable-write failure.
        result['candidates'] += 1
        if ingress(context_id, raw, f.copy()):
            result['admitted_stock_commands'] += 1
    return result
