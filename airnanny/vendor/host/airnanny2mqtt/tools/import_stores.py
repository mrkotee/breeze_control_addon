"""Stage durable stores into the add-on's own volume, once.

An add-on's data volume is not reachable from the shares an operator can
write to, so the stores are copied to a staging directory first and brought
in from there on startup.

Create-only, by construction. A context that already has a store is never
touched, never merged into and never overwritten. A store absent from both
places is left absent, because the service's own startup check reports that
more precisely than this can.

What that does not protect against is a stale staging copy meeting an empty
volume: a reinstall wipes the stores and the record of how far their counters
had got, and importing a month-old copy then puts the counters back where
they were that day with nothing left to notice. Create-only cannot see that,
because the volume it checks was just emptied. The guard is outside this
tool -- the caller enables staged import deliberately, from a switch the
platform keeps outside that volume -- and the staging copy is meant to be
deleted once the first import is confirmed.

The protected secrets beside a store are deliberately not carried across.
They are DPAPI-wrapped and cannot be unwrapped on Linux, the keys arrive as
add-on options instead, and secret material that does not travel cannot be
left behind in a shared directory.
"""
import argparse
from pathlib import Path
import shutil
import sys

CONTEXTS = (0, 1)
SECRETS_DIRECTORY = 'secrets'


class ImportFault(Exception):
    """The copy did not produce a usable store."""


def occupied(path):
    """Does a store already live here?

    An empty directory counts as absent: Home Assistant and the operator both
    create directories as a side effect, and refusing to import because one
    exists would be a trap rather than a safeguard.
    """
    return path.is_dir() and any(path.iterdir())


def strip_secrets(root):
    removed = []
    for directory in sorted(root.rglob(SECRETS_DIRECTORY)):
        if directory.is_dir():
            shutil.rmtree(directory)
            removed.append(str(directory.relative_to(root)))
    return removed


def verify(root):
    """A store we can recognise has at least one security epoch in it."""
    if not any(root.rglob('epoch.json')):
        raise ImportFault('no epoch.json under %s; this is not a context store' % root)


def import_context(staging, target):
    if occupied(target):
        return 'kept'
    if not occupied(staging):
        return 'absent'
    scratch = target.with_name(target.name + '.importing')
    if scratch.exists():
        shutil.rmtree(scratch)
    shutil.copytree(staging, scratch, symlinks=False)
    strip_secrets(scratch)
    try:
        verify(scratch)
    except ImportFault:
        shutil.rmtree(scratch)
        raise
    # Renamed into place only once it is complete and recognisable, so an
    # interrupted copy leaves no half-store for the next start to adopt.
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        # An empty directory left by the platform or the operator. Renaming
        # onto one succeeds on POSIX and fails on Windows, so it is removed
        # explicitly rather than relying on which host this runs on. Checked
        # again here because the only thing standing between this call and a
        # live store is that it is empty.
        if occupied(target):
            shutil.rmtree(scratch)
            raise ImportFault('%s filled while importing' % target)
        target.rmdir()
    scratch.rename(target)
    return 'imported'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--staging', required=True)
    p.add_argument('--target', required=True)
    args = p.parse_args(argv)

    staging, target = Path(args.staging), Path(args.target)
    for ctx in CONTEXTS:
        try:
            outcome = import_context(staging / ('ctx%d' % ctx), target / ('ctx%d' % ctx))
        except (ImportFault, OSError) as error:
            print('ctx%d import failed: %s' % (ctx, error), file=sys.stderr)
            return 1
        print({'imported': 'ctx%d store imported from staging' % ctx,
               'kept': 'ctx%d already has a store; staging ignored' % ctx,
               'absent': 'ctx%d has no store yet and none staged' % ctx}[outcome])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
