# V29: repeatable typed application TX — issue #6 offline candidate

**NOT FLASHED. Hardware PASS false.** V28 and its gate evidence are unchanged.

One behavioral change from V28: the typed TYPE07 path accepts a subsequent
command after the previous local TX completed successfully, provided its FC
is at least last_fc + 32. Only the per-cycle application_once rejection is
removed. All typed-envelope, context, epoch/attempt/guard/hash, readiness,
poll freshness, queue ownership, timeout and failure predicates remain.

INFO/STATUS/TXDONE advertise application_tx=typed_type07_repeat. Firmware
identity/version is airnanny_dual_pan_runtime_v29 / 29; wire remains RADIOV10.
The command stays TYPE07_FAN for wire compatibility; firmware remains blind
to encrypted application semantics. Python retains the frozen SAFE setters.

Repeated commands are new intents with fresh durable FC blocks, not retries.
A failed/unknown TYPE07 still stops its context. MAC retries remain limited to
the V28 retained-key recovery chain; no TYPE07 retry is added.

CDC disconnect/END, one BIND per boot and the bounded 3900-second session are
unchanged. Automatic recovery and indefinite operation are not claimed.

Native test test_application_repeat.c exercises the real typed predicate for
both contexts: repeated unique FCs, no pending resend/reuse, peer separation,
wrong PAN/RAW/guard/hash/generation and stale readiness, and failure STOP.
Inherited lifecycle and radio tests are reused where their contracts are
unchanged. Build tools perform no COM/RF/flash operations.
