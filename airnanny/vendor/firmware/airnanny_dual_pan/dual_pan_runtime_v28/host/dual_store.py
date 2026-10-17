"""Read-only access to both durable context stores.

The inherited host stack knows one context: host/management.py pins ctx1's run
and ctx1's RAW/TC, and every guard before this one treated ctx0's store as
something to inventory by hash and leave alone. Gate A is the first gate where
ctx0 has to become a live context, so both stores have to be readable at once.

This module never writes. It opens each store, checks it is the context it
claims to be, and returns what a BIND needs. Nothing here decrypts anything:
Gate A tests the immediate ACK, which is a clear-header property, and the keys
stay where they are.

The two stores live in different milestone lineages because they were
commissioned by different issues -- ctx0 by issue #3 and ctx1 by issue #4 --
and neither path is derivable from the other. They are pinned here, and a
mismatch between a store and the identity the firmware has compiled in is a
refusal rather than a warning: a store that does not match the image is either
the wrong store or a transplant, and both are reasons to stop before any radio
is configured.
"""
import hashlib
import json
from pathlib import Path

FIRMWARE = Path(__file__).resolve().parents[1]
MILESTONES = FIRMWARE.parent


class StoreFault(RuntimeError):
    pass


# The two durable stores, pinned by path. Verified present and matching on
# 2026-10-11; see evidence/dual_store_offline.json.
STORE_PATHS = {
    0: MILESTONES / 'hardware_commissioning_v7/.local/hardware_gate_v1/runs'
                    '/6ad64bba458744b1b085d0ba02bbc388/runtime/current/key/security/epoch.json',
    1: MILESTONES / 'second_a7_provisioning_v1/.local/hardware_gate_v2/runs'
                    '/7dd8634f2c1e491d9601be513519583b/runtime/current/key/security/epoch.json',
}

# What the image has compiled in, as include/dual_identity.h and
# src/dual_identity.c state it. Duplicated here on purpose and then checked
# against the C by tests/test_dual_store.py, so the C stays the single source of
# truth and a drift between them is a test failure rather than a silent
# disagreement discovered on hardware.
PINNED = {
    0: dict(pan=0xFA9B, short=0xA326,
            raw_ieee='e2b0275f4d582069', tc_ieee='00124b0036a148e5',
            keyseq=0, epoch='1ea30211ee014345a8288337a173a833',
            attempt='5b09cb6bc02746298fbffcfb780844a5'),
    1: dict(pan=0x0B7A, short=0x6C55,
            raw_ieee='027a56bb75a41437', tc_ieee='00124b0036a1875f',
            keyseq=0, epoch='9985b15dcb574c59b87dc2fb379f317f',
            attempt='cbef428849da4e87b48867ac616247d1'),
}

# The firmware refuses a BIND below this generation; include/dual_identity.h.
GENERATION_FLOOR = 6


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(ctx, path=None):
    """One context's store. Read-only, and strict: everything the image pins is
    compared, so the caller cannot bind a store that belongs to the other
    network or to an older identity."""
    if ctx not in STORE_PATHS:
        raise StoreFault('unknown_context:%r' % (ctx,))
    p = Path(path) if path is not None else STORE_PATHS[ctx]
    if not p.exists():
        raise StoreFault('store_missing:ctx%d:%s' % (ctx, p))

    r = json.loads(p.read_text(encoding='utf-8'))
    c = r.get('context') or {}
    want = PINNED[ctx]

    if c.get('ctx') != ctx:
        raise StoreFault('store_is_not_ctx%d:claims=%r' % (ctx, c.get('ctx')))
    for field, key in (('pan', 'pan'), ('short', 'short')):
        if c.get(field) != want[key]:
            raise StoreFault('ctx%d_%s_mismatch:store=%r image=%#06x'
                             % (ctx, field, c.get(field), want[key]))
    for field in ('raw_ieee', 'tc_ieee'):
        if (c.get(field) or '').lower() != want[field]:
            raise StoreFault('ctx%d_%s_mismatch:store=%r image=%s'
                             % (ctx, field, c.get(field), want[field]))
    if r.get('keyseq') != want['keyseq']:
        raise StoreFault('ctx%d_keyseq_mismatch:store=%r image=%r'
                         % (ctx, r.get('keyseq'), want['keyseq']))
    if (r.get('key_epoch_id') or '').lower() != want['epoch']:
        raise StoreFault('ctx%d_epoch_mismatch' % ctx)
    if (c.get('attempt') or '').lower() != want['attempt']:
        raise StoreFault('ctx%d_attempt_mismatch' % ctx)

    generation = r.get('generation')
    if not isinstance(generation, int) or generation < GENERATION_FLOOR:
        raise StoreFault('ctx%d_generation_below_floor:%r' % (ctx, generation))
    next_fc = r.get('next_fc')
    if not isinstance(next_fc, int) or next_fc < 32:
        raise StoreFault('ctx%d_next_fc_implausible:%r' % (ctx, next_fc))

    recovery = r.get('recovery') or {}
    guard = recovery.get('gate')
    if not isinstance(guard, str) or len(guard) != 32:
        raise StoreFault('ctx%d_guard_missing_or_malformed' % ctx)

    return {
        'ctx': ctx,
        'path': str(p),
        'epoch_sha256': _sha(p),
        'generation': generation,
        'next_fc': next_fc,
        'short': c['short'],
        'pan': c['pan'],
        'epoch': want['epoch'],
        'attempt': want['attempt'],
        'guard': guard,
        'keyseq': want['keyseq'],
        'recovery_state': recovery.get('state'),
        'context_generation': c.get('generation'),
        'nwk_source_floors': r.get('nwk_source_floors') or {},
    }


def read_both(paths=None):
    """Both stores, with the one check that only makes sense across them: the
    two contexts must not have collapsed onto the same tuple. A single radio
    answering one tuple for two networks is the failure the whole admission
    layer exists to prevent, and it would start here, in the stores, long
    before any frame."""
    paths = paths or {}
    out = {ctx: read(ctx, paths.get(ctx)) for ctx in sorted(STORE_PATHS)}
    a, b = out[0], out[1]
    if (a['pan'], a['short']) == (b['pan'], b['short']):
        raise StoreFault('both_stores_claim_the_same_tuple')
    if a['pan'] == b['pan']:
        raise StoreFault('both_stores_claim_the_same_pan')
    return out


def bind_fields(entry, session=1):
    """The field set the firmware's BIND requires, in its own spelling. The
    firmware refuses a BIND that omits or duplicates any of them, and refuses
    one whose epoch or attempt does not match the identity it has compiled in,
    so this is deliberately a direct projection of the store and not a place
    where values get chosen."""
    return ('session=%d generation=%d epoch=%s attempt=%s guard=%s short=%d'
            % (session, entry['generation'], entry['epoch'],
               entry['attempt'], entry['guard'], entry['short']))
