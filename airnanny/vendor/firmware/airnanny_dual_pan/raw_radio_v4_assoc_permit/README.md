# Authenticated permit association V4

Experimental admission-only successor to frozen V3. Wire prefix remains `RADIOV3`; INFO identifies `airnanny_raw_assoc_permit_v4`, version4. No complete commissioning, keys in firmware, production TX, MQTT or HA.

Two admission routes remain available:

- Existing `ASSOC BEGIN` references a fresh permit1/end-capacity beacon and rechecks it at REQUEST.
- New `ASSOC BEGIN_PERMIT_EVIDENCE` references an immutable raw RX cache record. The trusted host authenticates an A7-origin ZDO0036 with the selected live NWK context. Firmware checks boot/revision/SHA256, outer PAN/address/security-source bytes, ctx/generation/freshness and one-shot reservation. It cannot authenticate Zigbee MIC. SHA256 identifies public bytes and is not a Zigbee crypto/key implementation.

Permit V1 is deliberately narrower than general ZDO: ctx0/PAN FA9B, profile0, cluster0036, NWK0000→FFFC, MAC0000→FFFF, expected coordinator IEEE, duration180/significance1, key-sequence0 in the independently authenticated live context, freshness≤10s. Other durations/context changes require separate review. Existing beacon admission retains V3 behavior.

The captured Association Request/poll builders, response parser, state machine, ACK filter and radio driver are byte-for-byte identical to V3. V4 caches up to eight 46-byte secured broadcast candidates; no cache entry grants permission itself. Eight candidates can evict an old entry, causing a closed failure. Raw records are immutable except their one-shot consumed flag. Evidence is consumed before BEGIN radio setup, including setup failures. Boot/revision/hash/target/generation bindings prevent reuse; REQUEST rechecks the same reserved record’s ≤10s age. Loss blocks BEGIN until reboot. Reboot clears volatile evidence; durable host identity/attempt reservation forbids repeating a used/uncertain attempt.

`hardware_once.py` validates and captures live frames. After ≥15s baseline and current-context authentication, an operator marker arms the helper for exactly one fresh authenticated permit. The arm marker grants no radio permission by itself. Permit reception may precede the user's reply marker; the reply is not the physical button timestamp. To meet ≤10s freshness, the helper reserves a fresh durable identity and proceeds immediately on valid live evidence, without waiting for another user reply.

Explicit bounded plan: one REQUEST, at most two independently typed Data Request polls, interval≥500ms, timeout10s. No retry after failed/uncertain completion and no polling after terminal response. The host verifies every emitted MAC against the frozen captured builders. Success remains only `ASSOCIATED_UNKEYED`. After REQUEST the helper does not decrypt application/security traffic; Transport Key is retained only as opaque RX if received. END then terminal INFO run sequentially on the same CDC connection; restoration returns to exact frozen V17.

## Offline reproduction

Run `tools/test.py` with Python supporting the local Zig C runner; run `tools/build.py` with the existing ARM GCC7.3.1. Run `tools/verify.py` with Python/cryptography and the existing local Wireshark NWK oracle. Real encrypted fixtures contain no keys. Missing local oracle => tests fail; no READY claim.

Tests cover real historical136/hardware2059/hardware2164/hardware655, negative semantic/security/freshness/replay cases, actual firmware dispatcher/cache binding, preserved V3 regressions, and fake-serial success/reject/no-ACK/no-response flows. Synthetic allocator state exists only under ignored `.local` and temporary test directories; no hardware RAW identity is allocated during Part A.

See parent [combined software/hardware result](../AUTHENTICATED_PERMIT_ASSOCIATION_V1.md) and [machine evidence](../evidence/authenticated_permit_association_v1.json). Hardware results stay pending until the separately bounded attempt and V17/physical recovery are recorded.
