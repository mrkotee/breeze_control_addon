# SINGLE-PAN COMMISSIONING RESULT

**PASS — MANAGEMENT_PENDING.** Issue #1 hardware acceptance criteria are met.
V17 restored and verified; operator confirms both original A7/AirControl pairs
work with current data, no CHECK CASE and no re-pairing. No additional A7
reboots or recovery actions. STOP after recovery; no application readiness claim.

One run: `6ad64bba458744b1b085d0ba02bbc388`; terminal guard **FINISHED**, permanently disallows rerun.
Hardware interval: 2026-10-07 19:18:22–19:19:21 UTC+03:00.
Frozen V7 firmware and host security remain unchanged. Frozen failed V6 gate,
old attempts, gen2 seed, SDK, V17 and production Python remain unchanged.

| Step | Hardware evidence |
| --- | --- |
| Target | Second-bedroom A7, PAN FA9B, channel 21, TC 00124b0036a148e5 |
| RAW identity | e2b0275f4d582069; reused, no new identity |
| Baseline | Current authenticated ordinary TYPE06, revision 42 |
| Permit | Fresh authenticated post-ARM ZDO0036, duration180/significance1, MIC/replay checks PASS |
| Association | One request, one extended poll; clean exact response and ACK; no CCA recovery needed |
| Current short | A326, authoritative response, atomically committed; historical 8B0B unused |
| Key polling | Three bounded short-source polls; first eligible immediately after durable commit/ACK |
| No gap | One boot/session/USB; commit ACK→first poll 0ms; response→poll 78ms host time |
| Transport Key | RX revision124; one explicit protected TC secret, MIC PASS, exact RAW/TC/keyseq0, replay-new |
| Key durability | ASSOCIATED_UNKEYED gen4 → KEY_RECEIVED_PENDING_DURABILITY gen5 → KEY_INSTALLED gen6 |
| First secured FC | FC0, block0..31 durably reserved/burned before crypto; next_fc32 |
| Device Announce | Exactly one encrypted frame; self-decrypt/re-encrypt/MIC check PASS; local_tx_ok/MAC ACK |
| State | MANAGEMENT_PENDING; management_complete0/application_tx locked |
| Passive observation | 10s, 20 RX records; authenticated relayed RAW Device Announce at revision125 |
| Terminal radio | STOPPED, pending0, immediate_ack0, rx_drop0/out_drop0 |
| V17 recovery | SAFE64445/failed0, SERIAL3612/failed0, unique local INFO/DONE; both physical pairs confirmed |

Remaining listed passive exchanges (End Device Timeout, Node Descriptor,
Request Key, TC link-key Transport Key, Verify Key, Confirm Key and application
traffic addressed to RAW) were not observed within the bounded window. This
does not establish that these steps are optional or grant application readiness.
No management follow-up, TYPE07, second-PAN TX or application command was sent.

Exact encrypted Device Announce (MAC bytes without FCS):

```text
6188009bfa000026a30802fdff26a33c0028000000006920584d5f27b0e200aab8e30dd2d26739564ac1041344ad91d747827c5ea8e89e
```

`evidence/single_pan_commissioning_result.json` contains baseline/permit,
exact association/current short, all poll and completion timestamps, sanitized
Transport Key metadata, protected reference/epoch, replay floors, independent
sequence allocators, FC lease, one-shot intent, ciphertext RX and TX/ACK records,
passive analysis, recovery and final acceptance. No key bytes or TK plaintext.
`evidence/commissioning_analysis.json` documents observational decoding limits.

Validation: 32 FakePort tests using the actual V7 dispatcher, 14 USB failure
phase subcases, 96 CCA dispatcher checks, 115812 inherited dispatcher checks
and 20046 RX-ring checks PASS. Post-hardware protected inventory comparisons
and real installed-key public secret scan PASS. RF TX→ACK microsecond timing
is not exposed; all latency values above are host observations.

V7 SHA256: A48EBFD3C8A931C7C7D326EFACFC3589C67D1FDA293DE987751957453CD7DCBD.
V17 SHA256: 2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193.

STOP. This run must never be repeated or its key/FC state reset.
