"""Observe authenticated Leave during recovery without spending reply floors."""
from .mac import MAC


def recovery_leave(row, ledgers, decode, *, authentication_errors=(ValueError,)):
    if not row or row.get('kind') != 'RX':
        return False
    fields = row['fields']
    try:
        raw = bytes.fromhex(fields['mac'])
        mac = MAC.parse(raw)
    except ValueError:
        return False
    matches = [ledger for ledger in ledgers.values()
               if ledger.identity['pan'] == mac.destination_pan]
    if len(matches) != 1:
        return False
    ledger = matches[0]
    identity = ledger.identity
    if mac.destination != identity['short'] or mac.source_pan != identity['pan']:
        return False
    try:
        _, plain, metadata = decode(raw, ledger.key, identity['keyseq'], pan=identity['pan'])
    except authentication_errors:
        return False
    if (metadata['source_ieee'] != identity['tc_ieee']
            or metadata['nwk_dst'] != identity['short']
            or metadata['nwk_fcf'] & 3 != 1
            or len(plain) != 2 or plain[0] != 4):
        return False
    # Only Leave enters this durable observer. Ordinary REJOIN/TIMEOUT replies
    # retain their floor for the existing authentication/commit state machine.
    # The existing authority rejects old Leave replays before writing state.
    return ledger.observe_addressed(raw, int(fields['revision'])) == 'LEAVE'


def guard_recovery_reads(wire, ledgers, decode, *, error_type=RuntimeError,
                         authentication_errors=(ValueError,)):
    """Gate every runner read, including command waits and readiness polling."""
    original = wire.read
    def read(*args, **kwargs):
        row = original(*args, **kwargs)
        if recovery_leave(row, ledgers, decode, authentication_errors=authentication_errors):
            raise error_type('radio_authenticated_leave')
        return row
    wire.read = read
