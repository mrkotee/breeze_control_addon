"""Local lifecycle and allowlisted structured logging, without raw traffic/config."""
from collections import deque


class EventLog:
    def __init__(self, limit=1000): self.records = deque(maxlen=limit)
    def emit(self, category, **fields):
        allowed = {'device', 'request_id', 'command', 'reason', 'availability'}
        if set(fields)-allowed: raise ValueError('unsupported log fields')
        self.records.append(dict(category=category, **fields))


class RadioSession:
    """Stops daemon-owned callbacks/sends without changing frozen RadioTransport."""
    def __init__(self, backend):
        self.backend = backend
        self.running = False

    def send_frame(self, ctx_id, mac_bytes, tx_id, completion):
        if not self.running: return False
        def completed(identifier, status):
            if self.running: completion(identifier, status)
        return self.backend.send_frame(ctx_id,mac_bytes,tx_id,completed)

    def stop(self): self.running = False
