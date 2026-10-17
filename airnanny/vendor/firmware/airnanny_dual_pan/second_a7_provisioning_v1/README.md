# Second A7 provisioning — Issue #4

Independent ctx1 on PAN0B7A for A7 в спальне. Dedicated RAW IEEE: `027a56bb75a41437`.
Issue4 acceptance PASS: independent commissioning/key, retained-key secure rejoin,
Announce/Timeout, full60s normal readiness and exactly one confirmed adjacent FAN.
V17 is verified by INFO after operator restoration; both A7/controller pairs are
confirmed healthy. Final guard9754e7c3a9e54347b9ad51695d783ab2 is FINISHED/confirmed.
Key/identity and all counter/replay authority are retained; gen16/nextFC1088.
All354 protected ctx0 files remain unchanged. The final successful session used
no A7 pairing-button hold. All commissioning/control guards are single-use.

- [Result and remaining acceptance](SECOND_A7_PROVISIONING_RESULT.md)
- [Machine evidence](evidence/second_a7_provisioning_v1.json)
- [Operator handoff](HARDWARE_HANDOFF.md)
- [Commissioning HEX for manual flashing](releases/airnanny_ctx1_commission_v7.hex)
- [Reproducible target adaptation](prepare.py)
- [Fresh guarded entry point](retry_after_wrong_pan.py)

The generators above describe the original preparation. Do not rerun them or
overwrite the frozen review after hardware has started.

The source generator reuses V7 commissioning and the proven runner; the FAN
adapter reuses reviewed V22 code. ctx0 source/security files stay untouched.
No concurrent dual-PAN, scheduler or MQTT/HA transport is introduced.
