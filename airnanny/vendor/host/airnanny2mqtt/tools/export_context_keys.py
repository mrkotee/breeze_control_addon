"""Read the two context keys out of DPAPI once, for entry into the add-on.

Run this on the machine that commissioned the units, under the account that
owns the protected secrets. It opens no serial port, transmits nothing, and
touches no durable counter: it reads the stores to learn each context's secret
reference, unwraps that secret, and prints what the operator needs.

Two separate outputs, because they carry different risk. The digests are not
secret and go into the add-on's configuration file; printing them is the
default. The keys themselves are printed only when asked for explicitly, and
then they belong in the add-on's own form and nowhere else -- not in a file,
a ticket, a chat message, or a terminal left open.

Nothing here writes to disk. The protected secrets on this machine are left
exactly as they were, so this machine remains a working deployment.
"""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.deps'), str(ROOT / 'src'), str(ROOT / 'tools')]
sys.dont_write_bytecode = True

from airnanny.addon_keys import key_digest                       # noqa: E402
from run_radio_daemon import firmware_modules                    # noqa: E402

CONTEXT_LABELS = {0: 'ctx0 — second bedroom, PAN FA9B',
                  1: 'ctx1 — bedroom, PAN 0B7A'}


def read_context(ctx):
    """The secret reference and unwrapped key for one context."""
    firmware_modules()
    import gate_a_authority as authority
    import dual_ledger
    import dual_store
    from key_announce import ProtectedSecrets

    secrets = dual_ledger.secrets_root(ctx)
    if not secrets.is_dir():
        raise SystemExit('no protected secrets for ctx%d at %s' % (ctx, secrets))
    record = authority.load(dual_store.STORE_PATHS[ctx])
    ref = record.get('secret_ref')
    if not ref:
        raise SystemExit('ctx%d store carries no secret_ref' % ctx)
    return ref, ProtectedSecrets(secrets).get(ref).value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--reveal-keys', action='store_true',
                   help='also print the keys themselves; type them into the add-on form and clear the screen')
    args = p.parse_args(argv)

    if os.name != 'nt':
        raise SystemExit('the protected secrets can only be unwrapped on the machine that owns them')

    contexts = {ctx: read_context(ctx) for ctx in (0, 1)}
    if contexts[0][0] == contexts[1][0]:
        raise SystemExit('both stores name the same secret reference; refusing to report them')

    print('Add-on configuration (not secret):\n')
    for ctx, (ref, key) in contexts.items():
        print('  ctx%d_key_sha256: "%s"' % (ctx, key_digest(ref, key)))

    if not args.reveal_keys:
        print('\nThe keys themselves were not printed. Re-run with --reveal-keys when you')
        print('are ready to type them straight into the add-on form.')
        return 0

    print('\nNetwork keys — type these into the add-on form, then clear this screen:\n')
    for ctx, (ref, key) in contexts.items():
        print('  %s' % CONTEXT_LABELS[ctx])
        print('    %s\n' % key.hex())
    if contexts[0][1] == contexts[1][1]:
        # Expected for these units: the two PANs are separated by PAN id and
        # addresses, which the receive path checks before decryption, not by
        # holding different keys. Both fields still take their own digest,
        # because each is bound to its own context's secret reference.
        print('Both contexts use the same key. Enter it in both fields; the digests differ.')
    print('These were read from DPAPI and not written anywhere. Nothing on this')
    print('machine changed, so it remains a working deployment.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
