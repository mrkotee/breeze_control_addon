"""Opt-in passive TYPE06 observations for matching physical state to bytes."""
import json
from .application import Type06


class StatusObservations:
    def __init__(self, emit):
        self.emit=emit
        self.due=0
        self.seen={}

    def __call__(self, now, adapters):
        if now<self.due:return
        self.due=now+1000
        for slot,adapter in sorted(adapters.items()):
            snapshot=adapter.device.snapshot()
            if (not snapshot.status_valid or not snapshot.status_fresh
                    or snapshot.status_age_ms is None or snapshot.status_age_ms<0
                    or self.seen.get(slot)==snapshot.rx_revision):
                continue
            try:
                frame=Type06(bytes.fromhex(snapshot.raw_type06))
            except (TypeError,ValueError):
                continue
            # Only the already authenticated application status is projected.
            # No transport, configuration, secret, store or ledger is read.
            row=dict(device=snapshot.device,rx_revision=snapshot.rx_revision,
                     age_ms=snapshot.status_age_ms,raw_type06=frame.raw.hex(),
                     flags_raw=frame.flags)
            self.emit('STATUS_OBSERVATION '+json.dumps(row,sort_keys=True,separators=(',',':')))
            self.seen[slot]=snapshot.rx_revision
