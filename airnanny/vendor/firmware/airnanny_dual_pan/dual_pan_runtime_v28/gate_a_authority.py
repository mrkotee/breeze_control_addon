"""Gate A authority: what must be true before the dongle goes on air, and what
is allowed to have changed afterwards.

Separated from launch_gate_a.py so it can be tested offline. Everything here is
a pure function of files and dictionaries: no serial, no device, no radio, and
nothing is written. The launcher does the writing and the one-shot bookkeeping.

A correction to my own first draft, which is the most important thing in this
file. I had written it so that both stores LEAVE the protected inventory,
reasoning that ctx0 becomes a live participant in Gate A and its store
therefore legitimately moves. That is wrong for Gate A.

Gate A performs no secured transmission: it binds both contexts, listens, reads
the counters and ends. No frame counter is spent, no generation advances, and
nothing on the host writes a store -- dual_store is read-only by construction.
So the correct expectation for Gate A is that BOTH stores come out
byte-unchanged, and ctx0 stays in the protected inventory exactly as it has
since issue #4.

The relaxation belongs to Gate B, where the secured rejoin genuinely does
advance ctx0. Allowing it here would have meant shipping a guard that permitted
a store to move during a gate with no business moving it, and the permission
would have been invisible precisely because nothing would have exercised it.
The transitions() machinery below is kept, because Gate B needs it and because
Gate A asserts its strictest case -- that nothing moved at all.
"""
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MILESTONES = HERE.parent
FIRMWARE_ROOT = MILESTONES.parent
sys.path.insert(0, str(HERE / 'host'))
import dual_store

V17 = FIRMWARE_ROOT / 'airnanny_v17/releases/airnanny_status_v17_machine_serial.hex'
V17_HASH = '2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193'

PRIOR = MILESTONES / 'ctx1_rx_admission_v25'
PRIOR_RESULT = PRIOR / 'hardware_result.json'
INVENTORY_SOURCE = MILESTONES / 'second_a7_provisioning_v1/prepare.py'
INVENTORY_BEFORE = MILESTONES / 'second_a7_provisioning_v1/.local/protected_before.json'

IMAGE = HERE / 'releases/airnanny_dual_pan_runtime_v28.hex'
MANIFEST = HERE / 'evidence/build_manifest.json'
REVIEW = HERE / 'evidence/review.json'

# The one dongle, by exact identity. More than one match, or none, is a refusal
# rather than a choice.
DONGLE = {'vid': 0x1915, 'pid': 0x1337, 'serial': 'C625E0B966C1'}

# Identity fields that may never change in either store.
FROZEN_STORE_FIELDS = ('pan', 'short', 'raw_ieee', 'tc_ieee')
# Fields that may rise but never fall.
MONOTONIC_STORE_FIELDS = ('generation', 'next_fc')


class AuthorityFault(RuntimeError):
    pass


def sha(path):
    p = Path(path)
    if not p.exists():
        raise AuthorityFault('required_artifact_missing:%s' % p.name)
    return hashlib.sha256(p.read_bytes()).hexdigest()


def load(path):
    """A missing or malformed input is a refusal with a name, not a traceback.
    The operator reads this output on their own machine and needs to know which
    artifact is absent, not which line of Python noticed."""
    p = Path(path)
    if not p.exists():
        raise AuthorityFault('required_artifact_missing:%s' % p.name)
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except (ValueError, UnicodeDecodeError) as e:
        raise AuthorityFault('required_artifact_unreadable:%s:%s' % (p.name, e))


# -- the protected inventory, minus the two live stores ---------------------

def live_store_prefixes():
    """The two stores are relative to the firmware root in the inventory's own
    spelling, so they can be excluded from it by prefix."""
    out = []
    for ctx, p in dual_store.STORE_PATHS.items():
        out.append(str(p.relative_to(FIRMWARE_ROOT.parent)).replace('\\', '/'))
    return tuple(out)


# prepare.py excludes a path when ANY of its components is one of these.
INVENTORY_EXCLUDED = ('__pycache__', 'zig-global', 'zig-local')


def protected_inventory_fast(milestones=None, repo=None):
    """The same inventory prepare.py builds, but without walking into the
    directories it is going to discard.

    prepare.py uses rglob('*') and filters afterwards, so it enumerates every
    file under zig-global before throwing it away: two milestones alone hold
    1799 such files each. Over a network mount that is the whole cost of the
    check -- measured at roughly 330 seconds, against 1.8 seconds to stat the
    354 files that actually matter. Pruning those directories during the walk
    yields the identical set.

    prepare.py is another milestone's frozen file and is not edited. This is a
    reimplementation with the same semantics, and
    tests/test_gate_a_authority.py proves the two agree -- including the edge
    case that a FILE named zig-local is excluded too, because prepare.py tests
    every path component and pruning directories alone would miss it."""
    milestones = Path(milestones) if milestones else MILESTONES
    repo = Path(repo) if repo else MILESTONES.parents[1]
    result = {}
    for directory in sorted(milestones.iterdir()):
        if not directory.is_dir():
            continue
        local = directory / '.local'
        if not local.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(local):
            dirnames[:] = [d for d in dirnames if d not in INVENTORY_EXCLUDED]
            for name in filenames:
                if name in INVENTORY_EXCLUDED:
                    continue
                f = Path(dirpath) / name
                result[f.relative_to(repo).as_posix()] = sha(f)
    return result


def protected(inventory=None, exclude_live_stores=False):
    """The protected inventory, with this milestone's own scratch removed.

    `exclude_live_stores` is False for Gate A and must stay False: Gate A sends
    nothing secured and writes no store, so ctx0's entries stay sealed under
    the hashes they have had since issue #4. Only ctx0's store is ever in this
    inventory in the first place -- ctx1's belongs to the milestone that owns
    the inventory, which prepare.py skips -- so the asymmetry is real and is
    handled rather than assumed.

    Gate B, which does advance ctx0 through a secured rejoin, is the gate that
    passes True here and relies on transitions() instead."""
    if inventory is None:
        inventory = protected_inventory_fast()
        # second_a7_provisioning_v1 is prepare.py's own milestone and it skips
        # itself, so the fast walk must skip it too or the two disagree.
        own = 'firmware/airnanny_dual_pan/%s/.local/' % INVENTORY_SOURCE.parent.name
        inventory = {k: v for k, v in inventory.items() if not k.startswith(own)}
    mine = 'firmware/airnanny_dual_pan/dual_pan_runtime_v28/.local/'
    kept = {p: h for p, h in inventory.items() if not p.startswith(mine)}
    if exclude_live_stores:
        kept = _without_live_stores(kept)
    return kept


def _without_live_stores(inventory):
    live = live_store_prefixes()
    return {p: h for p, h in inventory.items()
            if not any(p.endswith(x) or x in p for x in live)}


def sealed_integrity(sealed=None, repo=None, live=None):
    """Every file the issue #4 inventory sealed must still be present and
    byte-identical. This is the anti-tamper check, and it is the strong half.

    Measured on the operator's machine on 2026-10-12: all 354 sealed files
    present and unmodified, and 274 files ADDED since the seal, spread across
    the ctx1_* milestones of the V22..V25 lineage -- run artifacts from gates
    that executed after issue #4 took its snapshot.

    That is why this is not a set comparison. Comparing the live inventory
    against the sealed one as a whole reports those 274 benign additions as
    failures, and the tempting response -- excluding milestone prefixes until
    the comparison passes -- weakens the check until it is green, which is the
    anti-pattern this whole guard exists to avoid. Splitting the question
    keeps the strong half strict: a sealed file that moved is a refusal, an
    added run artifact is reported and accounted for."""
    sealed = sealed if sealed is not None else load(INVENTORY_BEFORE)
    missing, modified = [], []
    if live is not None:
        # Compared against an inventory already in hand. This is the path the
        # real preflight takes: protected() has just hashed every live file, so
        # re-reading 354 of them from disk would be a second pass for nothing.
        for rel, digest in sealed.items():
            if rel not in live:
                missing.append(rel)
            elif live[rel] != digest:
                modified.append(rel)
    else:
        repo = Path(repo) if repo else MILESTONES.parents[1]
        for rel, digest in sealed.items():
            p = repo / rel
            if not p.exists():
                missing.append(rel)
            elif sha(p) != digest:
                modified.append(rel)
    return {'sealed_count': len(sealed), 'missing': sorted(missing),
            'modified': sorted(modified),
            'intact': not missing and not modified}


def additions_since_seal(inventory=None, sealed=None):
    """Files present now that the seal did not cover. Reported, not failed --
    but every one must sit under some milestone's .local run directory. One
    appearing anywhere else would mean the inventory's own shape changed, and
    that is a refusal rather than an addition."""
    live = protected(inventory)
    sealed = sealed if sealed is not None else load(INVENTORY_BEFORE)
    added = sorted(set(live) - set(sealed))
    stray = [a for a in added
             if not a.startswith('firmware/airnanny_dual_pan/')
             or '/.local/' not in a]
    return {'added': added, 'count': len(added), 'stray': stray}


def protected_unchanged(inventory=None, before=None, exclude_live_stores=False):
    """Kept under its inherited name and meaning for the callers: a non-empty
    result is a refusal. It now reports only what must never change -- sealed
    files that went missing or moved, and additions in places the inventory
    does not cover -- rather than every benign run artifact added since 2026."""
    sealed = before if before is not None else load(INVENTORY_BEFORE)
    live = inventory if inventory is not None else protected()
    if exclude_live_stores:
        # From BOTH sides. Dropping a store from the live inventory alone
        # turns a store that moved into a store that went MISSING, which is
        # still a refusal and a misleading one. What replaces this check for
        # the live stores is transitions(), which knows what may move.
        sealed = _without_live_stores(sealed)
        live = _without_live_stores(live)
    integrity = sealed_integrity(sealed, live=live)
    out = ['MISSING:' + x for x in integrity['missing']]
    out += ['MODIFIED:' + x for x in integrity['modified']]
    out += ['STRAY:' + x for x in additions_since_seal(live, sealed)['stray']]
    return out


# -- the prior gate ---------------------------------------------------------

PRIOR_EXPECTED = {
    'issue4_PASS': True,
    'guard_FINISHED': True,
    'clean_END': True,
    'final_V17_verified': True,
    'final_both_pairs_health_verified': True,
    'error': None,
}


def prior_closed(result=None, ctx1_epoch_sha=None):
    """Issue #4's gate must be closed and verified, and the ctx1 store today
    must still be the one it left. That second check is the lineage link: a
    store that moved since the prior gate closed has an unexplained history,
    and Gate A is not the place to discover it."""
    r = result if result is not None else load(PRIOR_RESULT)
    wrong = {k: r.get(k) for k, v in PRIOR_EXPECTED.items() if r.get(k) != v}
    if wrong:
        raise AuthorityFault('prior_gate_not_closed:%r' % wrong)
    if ctx1_epoch_sha is None:
        ctx1_epoch_sha = dual_store.read(1)['epoch_sha256']
    if r.get('final_CURRENT_sha256') != ctx1_epoch_sha:
        raise AuthorityFault(
            'ctx1_store_moved_since_the_prior_gate:prior=%r now=%r'
            % (r.get('final_CURRENT_sha256'), ctx1_epoch_sha))
    return r


# -- the software under test -------------------------------------------------

SDK_PREFIX = 'nrf sdk/'


def sdk_root(manifest):
    """Where the SDK is on THIS host.

    The manifest records sdk_root as the absolute path of the machine that
    built the image, which is a Windows path. The input hash KEYS were
    deliberately made repository-relative so the evidence travels between
    hosts; sdk_root was not, and that asymmetry made the check fail on any host
    but the build host -- found by running the preflight on the Linux VM.

    So the SDK is located the same way tools/build.py locates it, three levels
    above the repository root, and the recorded sdk_root is only a fallback for
    the host that happens to be the build host. If neither resolves it is a
    refusal naming both paths tried, because silently skipping the SDK inputs
    would drop roughly fifty files out of the very check that refuses an image
    built before the sources moved."""
    candidates = [HERE.parents[3] / 'nrf sdk']
    recorded = manifest.get('sdk_root')
    if recorded:
        candidates.append(Path(recorded))
    for c in candidates:
        if c.exists():
            return c
    raise AuthorityFault('sdk_root_not_found:tried=%r'
                         % [str(c) for c in candidates])

def software(review=None, manifest=None):
    """Everything that must be pinned before the image is flashed. The check
    that matters most is the manifest's input hashes: it is what refuses an
    image built before the sources moved, and it has already done so once in
    this work."""
    q = review if review is not None else load(REVIEW)
    m = manifest if manifest is not None else load(MANIFEST)

    if not q.get('passed') or q.get('hardware_performed') is not False:
        raise AuthorityFault('offline_review_required')
    for rel, digest in q.get('source_sha256', {}).items():
        if sha(HERE / rel).upper() != digest.upper():
            raise AuthorityFault('reviewed_source_changed:' + rel)
    sdk = sdk_root(m)
    for rel, digest in m.get('input_sha256', {}).items():
        if rel.startswith(SDK_PREFIX):
            p = sdk / rel[len(SDK_PREFIX):]
        else:
            p = HERE / rel
        if not Path(p).exists():
            raise AuthorityFault('firmware_input_missing:' + rel)
        if sha(p).upper() != digest.upper():
            raise AuthorityFault('firmware_input_changed:' + rel)
    if m.get('flashed') is not False:
        raise AuthorityFault('manifest_claims_flashed')
    if not m.get('bit_comparable_with_v17_to_v25_lineage'):
        raise AuthorityFault('image_not_bit_comparable_with_the_lineage')
    if sha(IMAGE).upper() != m['hex_sha256'].upper():
        raise AuthorityFault('image_does_not_match_its_manifest')
    if q.get('image_sha256', '').upper() != m['hex_sha256'].upper():
        raise AuthorityFault('reviewed_image_is_not_this_image')
    if sha(V17).upper() != V17_HASH:
        raise AuthorityFault('v17_reference_changed')
    return {'image_sha256': m['hex_sha256'], 'review_sha256': sha(REVIEW)}


# -- the stores, before and after -------------------------------------------

def snapshot(stores=None):
    s = stores if stores is not None else dual_store.read_both()
    return {str(ctx): {k: e[k] for k in
                       ('epoch_sha256', 'generation', 'next_fc', 'pan', 'short',
                        'recovery_state', 'context_generation', 'nwk_source_floors')}
            for ctx, e in s.items()}


def transitions(before, after, secured_frames_sent=False):
    """What Gate A is allowed to have changed. Returns the list of violations;
    an empty list is the only acceptable result.

    Gate A sends no secured frames, so the expected normal outcome is that
    next_fc did not move at all. A rise is not forbidden -- the firmware could
    legitimately have spent a counter -- but it must be stated, so it is
    reported as a finding when no secured frame was sent rather than silently
    accepted."""
    out = []
    for ctx in sorted(set(before) | set(after)):
        b, a = before.get(ctx), after.get(ctx)
        if b is None or a is None:
            out.append('ctx%s: a store appeared or vanished' % ctx)
            continue
        for f in FROZEN_STORE_FIELDS:
            if b.get(f) != a.get(f):
                out.append('ctx%s: %s changed, %r -> %r' % (ctx, f, b.get(f), a.get(f)))
        for f in MONOTONIC_STORE_FIELDS:
            if a.get(f, 0) < b.get(f, 0):
                out.append('ctx%s: %s decreased, %r -> %r' % (ctx, f, b.get(f), a.get(f)))
        for k, v in (b.get('nwk_source_floors') or {}).items():
            if (a.get('nwk_source_floors') or {}).get(k, 0) < v:
                out.append('ctx%s: replay floor for %s decreased' % (ctx, k))
        if not secured_frames_sent and a.get('next_fc') != b.get('next_fc'):
            out.append('ctx%s: next_fc moved %r -> %r although no secured frame '
                       'was sent; this needs an explanation, not an allowance'
                       % (ctx, b.get('next_fc'), a.get('next_fc')))
    return out


def gate_a_store_expectation(before, after):
    """Gate A's own, strictest case: nothing moved. Separate from transitions()
    so that the general rule and the rule for THIS gate cannot be confused,
    and so a later gate loosening the general rule cannot silently loosen this
    one."""
    out = []
    for ctx in sorted(set(before) | set(after)):
        b, a = before.get(ctx), after.get(ctx)
        if b is None or a is None:
            out.append('ctx%s: a store appeared or vanished' % ctx)
            continue
        if b.get('epoch_sha256') != a.get('epoch_sha256'):
            out.append('ctx%s: the store changed during a gate that sends '
                       'nothing secured and writes no store: %s -> %s'
                       % (ctx, str(b.get('epoch_sha256'))[:12],
                          str(a.get('epoch_sha256'))[:12]))
    # Belt and braces: the general rule must also hold.
    out += transitions(before, after, secured_frames_sent=False)
    return out


# -- the device --------------------------------------------------------------

def select_device(ports):
    """Exactly one positively identified dongle, or a refusal. Picking the
    first match of several would be choosing which radio to put on air."""
    matches = [p for p in ports
               if (getattr(p, 'vid', None), getattr(p, 'pid', None),
                   getattr(p, 'serial_number', None))
               == (DONGLE['vid'], DONGLE['pid'], DONGLE['serial'])]
    if len(matches) != 1:
        raise AuthorityFault('one_positively_identified_dongle_required:found=%d'
                             % len(matches))
    return {'port': matches[0].device, **DONGLE}
