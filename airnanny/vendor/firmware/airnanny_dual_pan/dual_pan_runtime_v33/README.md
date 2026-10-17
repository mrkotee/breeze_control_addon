# V33: recovery of a parent absent at startup

Candidate based on V32. On 2026-10-17 the operator reported flashing V33 and
both kits healthy. Serial identity and ctx1 cold partial startup/late join
were subsequently verified in run e442ce72ac1d48868863ee1ee56eb09a; operator
confirmed both kits working after that run. Reverse direction also passed in
run 9ed4e22e295343a58589c0f0a4d692fc, with both kits working afterward.
The 4800-second timer/CDC soak passed in run 86920f7f3a3e405d8261ab9d14a9bf92;
operator confirmed both kits working after the final recovery.
Application-only image: releases/airnanny_dual_pan_runtime_v33.hex, starting
at 0x1000. Preserve MBR/bootloader and both durable security stores.
SHA256: 42f3e7dde6c3dcaa06d7a915560ddd2b575cf902bd42cb67ea5f4ad69b8ab839.
All HEX data is within 0x1000..0x104b3; no MBR or bootloader data is present.

Completed offline: 2190 C checks, 1593 host unit tests, ten real loopback-MQTT
tests and twelve actual-C/disposable-ledger scenarios. The image matches its
build manifest and the radio driver matches V32. Hardware scope is recorded below.

V33 advertises `application_tx=typed_type07_repeat_late_join` in INFO and
STATUS. STATUS adds `config_generation` and `late_join_restartable`.
The latter is explicit evidence of a clean recovery stop, not a blanket
permission to reopen any stopped session. BIND may resume such a context
only with a new guard, matching identity/short and nondecreasing generation.
It retains the old FC floor and does not republish its unchanged address
table or toggle the healthy context's ACK gate. Unknown cleanup, generic
stops and active application failures cannot authorize this path.

After the firmware captures a candidate response it starts no more automatic
response-window polls; the host must authenticate the response and wait for
any existing poll to settle before committing it. Invalid/replayed responses
do not permit the host to activate a context. Radio driver and ACK admission
are byte-identical to V32. Native evidence constrains the firmware delta to
src/main.c, src/rejoin_transport.c and include/commission.h.

The host uses one serial owner and one monotonically increasing command-id
allocator for runtime and recovery. Discovery/backoff of the missing parent
does not reboot the dongle or replace the healthy device. Completed recovery
installs only the new slot and waits for startup time and 40 completed
parent polls before admitting its commands. Fresh status and a genuine
template remain mandatory. No saved FAN-capture loader is used.

Offline entry points, with no radio or real key resolution:

- `python tools/native_build.py`
- `python tools/test_runtime.py`
- `python tools/wire_surface.py`
- `python tools/build.py --gcc-root <ARM GCC bin directory>`
- From host/airnanny2mqtt: `python tools/test_late_join_offline.py`

The last command drives the actual C dispatcher and real disposable ledgers
with synthetic keys. It covers both return directions, healthy commands
during absence, ordinary recovery misses/timeouts, timer wrap, bad MIC,
authenticated Leave and missing TX terminal. Local MQTT tests independently
check unavailable-slot rejection, admission and confirmed command results.

After manual flash, use the explicit host profile:
`python tools/run_radio_service.py --firmware-version 33 --preflight`.
For actual service add broker options instead of --preflight. V33 defaults to
partial startup, current-session stock handoff and successor 2. The default
firmware profile without --firmware-version remains the hardware-tested V32.
The selected firmware profile must match the flashed application.

Hardware completed: ctx1 absent at cold startup; ctx0 confirmed FAN while ctx1
was off; ctx1 command rejected without FC; automatic same-session ctx1 return;
40 readiness polls; live-template FAN confirmations on both slots; post-run
operator health. Source archive, key identities and monotonic floors verified.
Reverse direction also passed with live FAN5 confirmations on both A7 and
post-run operator health. The combined timer/CDC soak also passed: real timer
wrap, both FAN confirmations before/after wrap, actual CDC close, new boot,
and both final FAN confirmations using current-session live templates.
Service, disposable broker and sleep hold were closed; key identities and
monotonic source floors were verified. This does not claim physical proof of
every setter. Stock display disagreement is excluded by the operator.
