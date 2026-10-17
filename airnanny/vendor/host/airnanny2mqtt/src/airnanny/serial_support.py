"""Protocol-independent serial primitives; no firmware commands or radio access.

The caller owns the nonblocking port and pumps it on the daemon owner thread.
An empty read means no bytes available, not EOF. Disconnects must be surfaced
by the port as an exception or is_open=False. A failed channel is never reused.
"""
from collections import deque
from dataclasses import dataclass
import threading
from typing import Protocol


class SerialFault(ConnectionError):
    pass


class BytePort(Protocol):
    is_open: bool
    def read(self, size: int) -> bytes: ...
    def write(self, data: bytes) -> int: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class SerialLimits:
    line_bytes: int = 2048
    ingress_records: int = 128
    egress_records: int = 32
    read_bytes: int = 4096

    def __post_init__(self):
        if any(type(v) is not int or v <= 0 for v in vars(self).values()):
            raise ValueError('positive integer serial limits required')


class SerialChannel:
    """Bounded ASCII lines and partial writes, with a latched fail-closed fault.

    read/write must be nonblocking (including a bounded write timeout). One
    pump performs at most one read and one write. No callbacks run here.
    Records exclude LF; CRLF is accepted. Empty/control/non-ASCII lines fail
    the session, because recovering past an unknown completion is unsafe.
    """
    def __init__(self, port: BytePort, limits: SerialLimits = SerialLimits()):
        self.port, self.limits = port, limits
        self._owner = threading.get_ident()
        self._partial = bytearray()
        self._incoming = deque()
        self._outgoing = deque()
        self._offset = 0
        self.closed = False
        self.reason = None

    def _assert_owner(self):
        if threading.get_ident() != self._owner:
            raise RuntimeError('serial owner thread required')

    def _check(self):
        self._assert_owner()
        if self.closed:
            raise SerialFault(self.reason or 'serial_closed')

    @property
    def depths(self):
        self._assert_owner()
        return dict(ingress=len(self._incoming), egress=len(self._outgoing),
                    partial_bytes=len(self._partial))

    def close(self, reason='serial_shutdown'):
        self._assert_owner()
        if self.closed:
            return
        self.closed, self.reason = True, reason
        self._incoming.clear()
        self._outgoing.clear()
        self._partial.clear()
        self._offset = 0
        try:
            self.port.close()
        except Exception:
            pass  # The original fault remains authoritative.

    def _fail(self, reason):
        self.close(reason)
        raise SerialFault(reason)

    def submit_line(self, line: bytes):
        self._check()
        if (not isinstance(line, bytes) or not line or
                len(line) > self.limits.line_bytes or
                any(b < 32 or b > 126 for b in line)):
            raise ValueError('expected bounded printable ASCII without newline')
        if len(self._outgoing) >= self.limits.egress_records:
            self._fail('serial_egress_overflow')
        self._outgoing.append(line + b'\n')

    def _ingest(self, chunk):
        if not isinstance(chunk, bytes) or len(chunk) > self.limits.read_bytes:
            self._fail('serial_invalid_read')
        for b in chunk:
            if b == 10:
                line = bytes(self._partial)
                self._partial.clear()
                if line.endswith(b'\r'):
                    line = line[:-1]
                if not line or any(c < 32 or c > 126 for c in line):
                    self._fail('serial_malformed_line')
                if len(self._incoming) >= self.limits.ingress_records:
                    self._fail('serial_ingress_overflow')
                self._incoming.append(line)
            else:
                if b != 13 and not 32 <= b <= 126:
                    self._fail('serial_malformed_line')
                # CR can occur only as the final byte preceding LF.
                if self._partial.endswith(b'\r'):
                    self._fail('serial_malformed_line')
                if len(self._partial) >= self.limits.line_bytes + (b == 13):
                    self._fail('serial_line_overflow')
                self._partial.append(b)

    def pump(self):
        self._check()
        try:
            if not self.port.is_open:
                self._fail('serial_disconnected')
            self._ingest(self.port.read(self.limits.read_bytes))
            if self._outgoing:
                remainder = self._outgoing[0][self._offset:]
                written = self.port.write(remainder)
                if type(written) is not int or not 0 <= written <= len(remainder):
                    self._fail('serial_invalid_write')
                self._offset += written
                if self._offset == len(self._outgoing[0]):
                    self._outgoing.popleft()
                    self._offset = 0
        except SerialFault:
            raise
        except Exception:
            self._fail('serial_io_error')

    def pop_line(self):
        self._check()
        return self._incoming.popleft() if self._incoming else None
