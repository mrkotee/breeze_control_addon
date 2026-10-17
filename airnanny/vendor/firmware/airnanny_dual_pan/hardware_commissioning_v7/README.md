# Issue #1: single-PAN commissioning with reviewed V7

This sibling reuses the frozen V7 SingleBoot, security backend, crypto, replay,
durable counter policy and exact firmware. It preserves the failed V6 hardware
gate and its attempt; no earlier guard or state is reset.

Run `verify.py` with the bundled modern Python before hardware. It tests the
runner against the actual V7 C dispatcher with FakePort, compares protected
inventories and scans public files for protected/captured secrets. It never
opens serial. See `evidence/part_a.json` for hashes and checks.

The only scheduling change from the reviewed V6 live runner is calling V7's
existing `association_poll_due()` predicate after draining RX. One request;
max two extended polls. Only the first poll's mapped CCA permits recovery,
at least 3200us after completion receipt. A response during recovery cancels
poll2. All other errors stop. No independent retry policy exists here.

One boot/USB/session continues through association, durable current-short
commit, immediate key-poll eligibility, max8 key polls / 500ms / 10s, exact
one-TC authentication, protected durable key install, KEY_STATE acknowledgment,
FC0 block0..31 burned with next_fc32, self-checked encrypted one-shot Device
Announce, and 10s passive observation. Only MANAGEMENT_PENDING is reachable.
No TYPE07 or subsequent management commands are provided.

Before hardware, confirm both pairs/current data/no CHECK CASE, automation
paused, and original requested device settings. `runner.py start --physical`
creates a permanent milestone claim and fresh run UUID. Its directory is
`.local/hardware_gate_v1/runs/<UUID>`. The claim prevents a second attempt even
after recovery. Run start never opens serial or reserves an association attempt.

The operator manually flashes the exact V7 application image without erasing
MBR/bootloader/data. After the operator confirms completion, record immutable
`v7_flashed.json` with the exact SHA256. `runner.py execute --run <UUID>` opens
COM7 once. Enable selected second-bedroom A7 pairing once only after
PERMIT_ARMED is observed. No prompts or USB reopen occur after association.

After the run, manually restore frozen V17, then `inspect-recovery --run <UUID>`
issues one local INFO. Confirm both original pairs work/current data/no CHECK
CASE/no re-pairing and record any reboot or recovery action. `finish --run
<UUID> --physical <JSON>` reconciles the immutable terminal result and writes
`SINGLE_PAN_COMMISSIONING_RESULT.md` and
`evidence/single_pan_commissioning_result.json`. STOP after recovery.

V7 SHA256: A48EBFD3C8A931C7C7D326EFACFC3589C67D1FDA293DE987751957453CD7DCBD.
V17 SHA256: 2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193.

Evidence distinguishes FakePort from hardware. It records ciphertext RX,
host completion timestamps, clean ACK flags, authoritative short, protected
references, public epoch/high-water, exact announce intent and physical recovery.
RF TX-to-ACK microsecond timing is not exposed by V7; host latency is separate.
Passive encrypted observations cannot establish absent management exchanges;
do not report their semantics without an authenticated decode.
