# V4 permit-evidence extension to RADIOV3

Transport retains V3 printable ASCII, LF, ≤511 characters and strictly increasing host id per boot. Only INFO is boot-independent. INFO adds exact version4 identity, `permit_gate=beacon_or_authenticated_zdo`, `transport_key=unsupported`, `device_announce=unsupported`, mirrored `immediate_ack` and `pending_tx` diagnostics.

```text
RADIOV3 ASSOC BEGIN_PERMIT_EVIDENCE boot=<hex32> id=<u32> ctx=0 raw_ieee=<canonicalhex16> target_pan=fa9b extpan=<coordinatorhex16> coordinator_ieee=<canonicalhex16> coordinator_short=0000 policy=local_experimental_v1 attempt=<hex32> permit_revision=<u32> raw_hash=<sha256hex64> validation_generation=<u32> max_polls=2 poll_interval_ms=500 timeout_ms=10000 dsn=30
```

Exactly this field set is accepted; no `session` or `beacon_revision` on this command. Hash order is conventional SHA256 over MAC bytes without PHY length/FCS, as emitted in RX. Boot/revision refer to the current device stream. Validation generation is host attempt context and monotonic within the firmware boot. Other fields preserve existing typed identity/target policy. Unknown, duplicate, boolean unlock or raw upload fields are rejected.

The command is a dedicated trusted-host declaration of authenticated ZDO permit class. Firmware verifies the record binding and outer target bytes, not the encrypted APS/ZDO semantics or MIC. A malicious local host with access to this command could falsely declare validation; no cryptographic security against that host is claimed. The experimental helper enforces actual MIC/current epoch/replay-new/profile0/cluster0036/duration180/significance1 verification.

Successful BEGIN echoes `admission_evidence=zdo_permit`, exact permit revision and validation generation, plus the new session/attempt. Existing beacon BEGIN echoes `admission_evidence=beacon`. No session has neither path. Existing REQUEST/POLL/STATUS/END syntax remains unchanged; REQUEST references the selected session and rechecks its reserved admission record. END disables ACK. None of these commands can install a key or send arbitrary MAC/NWK/APS payloads.

Cache/hash/freshness/target/generation failures are explicit errors and do not grant a session. Consumed records cannot be reused even after cancellation or local radio setup failure. The existing one-request and typed poll limits remain in the unchanged state machine. Only exact CC63/command02/session-target/newer-revision Association Response can be auto-ACKed.
