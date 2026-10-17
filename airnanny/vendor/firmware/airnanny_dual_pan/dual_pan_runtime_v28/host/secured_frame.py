"""Building a secured management frame, with no authority to write anything.

Extracted from Ledger._build so that the two paths that need it -- the
offline model and the Gate B launcher, which is the only component allowed to
move a real store -- share ONE copy of the most consequential code in the
project rather than each keeping their own. A second copy of frame building
would be a second place for the aux header, the frame counter and the key to
disagree, which is precisely the separation issue #5 exists to prove:

    frame ctx == key ctx == RAW IEEE ctx == FC allocator ctx

This module deliberately has no store access, no file access and no serial
access. It takes the numbers it is given and returns bytes. Deciding WHICH
numbers -- reserving the frame counter, advancing the sequences, enforcing
one-shot state -- stays with whoever owns the store, because that is the part
that must be durable and refused when it cannot be.

The one thing that changed in the extraction is the PAN. Ledger._build wrote
`le(0x0b7a)` inline: ctx1's PAN, hardcoded, because V25 had one context. A
dual runtime that kept that constant would address ctx0's frames to ctx1's
network while encrypting them with ctx0's key -- the exact cross-context
failure the gates are built to catch, introduced by a literal. It is a
parameter here, and build_secured refuses a tuple whose parts do not belong
to the same context.
"""
import hashlib

from management import le, ieee, decode_nwk
from recovery_model import encrypt, Fault

# Wire length per kind, as V17..V25 measured them. A frame of the wrong length
# is refused before it can be handed to a radio.
LENGTH = {'REJOIN': 53, 'ANNOUNCE': 55, 'TIMEOUT': 54}
KINDS = tuple(LENGTH)


def dsn_step(kind):
    """How far the MAC sequence number advances for this kind. REJOIN and
    TIMEOUT step by 6 because the firmware emits intervening frames; ANNOUNCE
    steps by 1. Carried over from Ledger._build unchanged."""
    return 6 if kind in ('REJOIN', 'TIMEOUT') else 1


def build_secured(kind, *, pan, short, fc, sequences, key, raw_ieee, tc_ieee,
                  keyseq=0):
    """The frame bytes for one secured management kind, self-checked.

    `sequences` is the dict of counters as they were BEFORE this frame
    (`nwk`, `dsn`, and for ANNOUNCE also `aps` and `zdo`); the caller owns
    advancing them durably. Every other argument belongs to one context and
    must belong to the SAME one -- that is what the self-check below proves,
    by decoding the frame it just built with the key it was given and
    comparing the result to what it meant to say.
    """
    if kind not in LENGTH:
        raise Fault('NO_GENERIC_OR_TYPE07')
    if not 0 < short < 0xfff8 or not 0 <= pan <= 0xfffe:
        raise Fault('implausible_tuple:pan=%r short=%r' % (pan, short))
    if fc + 31 > 0xfffffffe:
        raise Fault('FC_exhaustion')

    seq = sequences
    mac = b'\x61\x88' + bytes([seq['dsn']]) + le(pan) + le(0) + le(short)
    if kind == 'ANNOUNCE':
        h = b'\x08\x02' + le(0xfffd) + le(short) + b'\x3c' + bytes([seq['nwk']])
        p = (b'\x08\0\x13\0\0\0\0' + bytes([seq['aps'], seq['zdo']])
             + le(short) + ieee(raw_ieee) + b'\x80')
    else:
        h = (b'\x09\x1a' + le(0) + le(short) + b'\x01' + bytes([seq['nwk']])
             + ieee(tc_ieee) + ieee(raw_ieee))
        p = b'\x06\x80' if kind == 'REJOIN' else b'\x0b\x08\0'

    raw = mac + encrypt(h, b'\x28' + le(fc, 4) + ieee(raw_ieee) + b'\0', p, key)

    # Self-check: decode what was just built, with the key it was built with.
    # A frame whose aux header, counter or source identity does not come back
    # as intended is never handed to a radio -- on air it would spend a frame
    # counter that can never be reused and might reach the wrong network.
    _, plain, meta = decode_nwk(raw, key, keyseq, pan=pan)
    if plain != p:
        raise Fault('self_check_payload')
    if meta['counter'] != fc:
        raise Fault('self_check_counter:%r != %r' % (meta['counter'], fc))
    if meta['source_ieee'] != raw_ieee:
        raise Fault('self_check_source_ieee')
    if len(raw) != LENGTH[kind]:
        raise Fault('self_check_length:%d != %d' % (len(raw), LENGTH[kind]))
    # The PAN the frame will actually be addressed to, read back off the wire
    # bytes rather than trusted from the argument: this is the one that used
    # to be a hardcoded constant.
    if int.from_bytes(raw[3:5], 'little') != pan:
        raise Fault('self_check_pan')
    return raw, hashlib.sha256(raw).hexdigest()


def advance(sequences, kind):
    """The sequence counters as they must be AFTER this kind, returned rather
    than mutated: the caller decides when that becomes durable."""
    out = dict(sequences)
    out['nwk'] = (sequences['nwk'] + 1) & 255
    out['dsn'] = (sequences['dsn'] + dsn_step(kind)) & 255
    if kind == 'ANNOUNCE':
        for name in ('aps', 'zdo'):
            out[name] = (sequences[name] + 1) & 255
    return out
