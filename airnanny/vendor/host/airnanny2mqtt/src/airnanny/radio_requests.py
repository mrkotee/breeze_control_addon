"""Bounded owner-thread TX correlation independent of the firmware wire format.

No keys, counters, application confirmation, retry, or context reconstruction.
The reviewed protocol adapter must translate its typed results into these calls.
"""
from collections import OrderedDict
from dataclasses import dataclass
import threading
from typing import Callable
from uuid import uuid4
from .binary import CodecError
from .context import route
from .mac import MAC
from .serial_support import SerialFault


def validate_rx_context(context_id, raw, contexts):
    """Cross-check an explicit host context against clear MAC routing pre-decrypt.

    The future adapter must map the firmware slot and config generation to a
    durable host context before calling this. This never consults any keys.
    """
    selected = route(MAC.parse(raw), contexts)
    if selected.identity != context_id:
        raise CodecError('radio record context mismatch')
    return selected


@dataclass
class _Pending:
    context: str
    tx_id: str
    completion: Callable[[str, int], None]
    accepted: bool = False


class RadioRequests:
    """Each connection gets a fresh nonce; IDs never repeat across reconnects.

    Reserve BEFORE writing bytes. A queue rejection returns None; callers
    must not undo an already reserved secured frame counter. Accepted marks
    firmware acceptance only. Finish status zero means local completion only.
    Duplicate identical results in bounded history are ignored; conflicting,
    unknown, stale, or wrong-context results fail the entire session. Results
    evicted from history become unknown (fail closed), never silently ignored.
    """
    def __init__(self, contexts, *, pending_limit=32, history_limit=128):
        if any(type(v) is not int or v <= 0 for v in (pending_limit, history_limit)):
            raise ValueError('positive request limits required')
        self.contexts = frozenset(contexts)
        if not self.contexts or any(not isinstance(c, str) or not c for c in self.contexts):
            raise ValueError('explicit context identities required')
        self.pending_limit, self.history_limit = pending_limit, history_limit
        self._owner = threading.get_ident()
        self._nonce, self._sequence = uuid4().hex, 0
        self._pending = {}
        self._history = OrderedDict()
        self.closed = False
        self.reason = None

    def _assert_owner(self):
        if threading.get_ident() != self._owner:
            raise RuntimeError('radio request owner thread required')

    def _check(self):
        self._assert_owner()
        if self.closed:
            raise SerialFault(self.reason)

    @property
    def pending_count(self):
        self._assert_owner()
        return len(self._pending)

    def reserve(self, context, tx_id, completion):
        self._check()
        if context not in self.contexts or not isinstance(tx_id, str) or not tx_id or not callable(completion):
            raise ValueError('invalid TX request')
        if any(p.tx_id == tx_id for p in self._pending.values()):
            raise ValueError('duplicate pending core TX id')
        if len(self._pending) >= self.pending_limit:
            return None
        self._sequence += 1
        identifier = f'{self._nonce}:{self._sequence}'
        self._pending[identifier] = _Pending(context, tx_id, completion)
        return identifier

    def _fail(self, reason):
        self.close(reason)
        raise SerialFault(reason)

    def _lookup(self, identifier, context):
        pending = self._pending.get(identifier)
        if pending is None:
            self._fail('radio_unknown_request')
        if pending.context != context:
            self._fail('radio_wrong_context')
        return pending

    def accepted(self, identifier, context):
        self._check()
        self._lookup(identifier, context).accepted = True

    def finish(self, identifier, context, status):
        self._check()
        if type(status) is not int:
            self._fail('radio_invalid_result')
        if identifier in self._history:
            if self._history[identifier] != (context, status):
                self._fail('radio_conflicting_result')
            return False
        pending = self._lookup(identifier, context)
        if not pending.accepted:
            self._fail('radio_result_before_acceptance')
        del self._pending[identifier]
        self._history[identifier] = (context, status)
        if len(self._history) > self.history_limit:
            self._history.popitem(last=False)
        # Remove before invoking the core so reentrant completion cannot run twice.
        try:
            pending.completion(pending.tx_id, status)
        except Exception:
            try:
                self.close('radio_callback_error')
            except Exception:
                pass  # close attempted every other callback; preserve first error.
            raise
        return True

    def close(self, reason='radio_shutdown'):
        self._assert_owner()
        if self.closed:
            return
        self.closed, self.reason = True, reason
        pending, self._pending = self._pending, {}
        self._history.clear()
        error = None
        for p in pending.values():
            try:
                p.completion(p.tx_id, -1)
            except Exception as exc:
                error = error or exc
        if error is not None:
            raise error  # All pending callbacks have still been attempted.
