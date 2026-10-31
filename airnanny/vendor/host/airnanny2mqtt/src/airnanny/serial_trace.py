"""Remember the last bytes read from the dongle, for when they make no sense.

The reviewed wire reader refuses a line whose first token is not the protocol
prefix, and raises without recording it -- reasonably, since it cannot say
what an unparsable line was. The effect on an appliance is that
UNEXPECTED_SERIAL_PROTOCOL arrives with no evidence at all: the retained
trace holds every line that parsed and nothing about the one that did not,
and there is no shell on the box to go and look.

This wraps the port and keeps a bounded tail of everything read through it,
so the failure trace can carry what was actually on the wire. It is a
pass-through and nothing else: no buffering, no retries, no interpretation.
Whatever the reviewed reader would have seen, it still sees, in the same
order and the same chunks.

Nothing secret crosses this link. The firmware is `crypto=host_only`: it
moves frames and never holds a key, and the frames the host hands it are
already sealed. The tail is bounded and escaped on the way out, so a stray
binary device cannot write control characters into a log either.
"""

PRINTABLE_LIMIT = 512
TAIL_BYTES = 2048


class WatchedPort:
    """A serial port that also remembers the last bytes read from it."""

    _OWN = ('_port', '_limit', 'seen')

    def __init__(self, port, limit=TAIL_BYTES):
        if type(limit) is not int or limit <= 0:
            raise ValueError('positive byte limit required')
        object.__setattr__(self, '_port', port)
        object.__setattr__(self, '_limit', limit)
        object.__setattr__(self, 'seen', bytearray())

    # -- pass-through -----------------------------------------------------

    def read(self, size):
        data = self._port.read(size)
        if data:
            self.seen.extend(data)
            excess = len(self.seen) - self._limit
            if excess > 0:
                del self.seen[:excess]
        return data

    def write(self, data):
        return self._port.write(data)

    def close(self):
        return self._port.close()

    # Delegated rather than copied: a port's `timeout`, `in_waiting` and
    # `is_open` are live properties of the real object, and a copy would go
    # stale the moment the device changed state. Assignment is forwarded too,
    # because callers set `timeout` on the port they were handed.
    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, '_port'), name)

    def __setattr__(self, name, value):
        if name in self._OWN:
            object.__setattr__(self, name, value)
        else:
            setattr(self._port, name, value)

    # -- evidence ---------------------------------------------------------

    def tail(self, limit=PRINTABLE_LIMIT):
        """The recent bytes, escaped so they are safe to put in a log.

        Returns None when nothing was ever read, which is itself a finding:
        the port produced no bytes at all, rather than wrong ones.
        """
        if not self.seen:
            return None
        if type(limit) is not int or limit <= 0:
            raise ValueError('positive printable limit required')
        return printable(bytes(self.seen[-limit:]))


def printable(data):
    """Escape bytes for a log: one line, no control characters, no colour."""
    out = []
    for byte in data:
        character = chr(byte)
        if character == '\n':
            out.append('\\n')
        elif character == '\r':
            out.append('\\r')
        elif character == '\t':
            out.append('\\t')
        elif 0x20 <= byte < 0x7f:
            out.append(character)
        else:
            out.append('\\x%02x' % byte)
    return ''.join(out)
