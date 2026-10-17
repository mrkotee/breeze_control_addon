# RADIOV3 provisioning — draft, NOT IMPLEMENTED

2026-10-06, evidence verdict B. No RADIOV3 firmware/HEX exists. These messages are a proposed typed contract for a later reviewed implementation; sending them to RADIOV2 does not unlock TX. All unsupported/unproved classes must reject. No `OWNED=1` or arbitrary production RAW TX command.

## Session and identity binding

`RADIOV3 INFO id=<u32>` -> firmware identity/protocol, random per-boot `boot=<hex32>`, support bitmap, `provisioning_ready=0` until actual implementation/tests exist, production gate locked. RX may be observed independently.

Proposed `RADIOV3 PROVISION BEGIN id=... boot=... ctx=0|1 generation=... raw_ieee=<canonical hex16> pan=<hex4> extpan=<hex16> channel=21 coordinator_ieee=<hex16> coordinator_short=0000 policy=<reviewed policy version> attempt=<opaque id>`.

One session at a time, bound to exact boot, context, immutable IEEE/target and allocation policy. BEGIN creates only an unkeyed commissioning session. It cannot assert durable production ownership. The host must prove uniqueness locally and persist allocation/attempt before BEGIN; the firmware cannot independently know whether an arbitrary IEEE was used on another device. Thus session binding is containment, not cryptographic proof of a never-used identity. No spoofed use of AirControl/V17 identities is permitted.

Firmware session phases begin UNKEYED. Address/phase mutation requires typed accepted management events and monotonically increasing session generation; no caller-controlled shortcut to JOINED. Association response validation binds incoming destination IEEE, PAN, coordinator IEEE and valid assigned short. Opaque firmware cannot verify APS MIC or key durability: those checks remain host responsibilities. A host receipt may carry a store generation/lease token; it is not verifiable durable-storage proof in firmware. Do not claim otherwise.

`RADIOV3 PROVISION TX id=... boot=... session=... generation=... phase=... class=... intent=... mac=<hex>`.

Validate ASCII/token count, boot/session/generation, bounded frame length<=125 without FCS, entire MAC header, destination/source/PAN, command identifier/payload length, class/phase budget. No IEEE replacement within a session; no ctx1 TX while ctx0 provisioning active. Allocate monotonic TX ID only after acceptance; bounded queue; exactly one TXACCEPT or TXREJECT and one eventual TXDONE per accepted ID in that boot. No automatic retransmit after uncertain TX. Completion includes driver status, ACK result and exact session/intent; local ACK is not key verification/join proof.

`RADIOV3 PROVISION STATUS id=... boot=... session=...` -> phase, immutable bindings, last accepted TX/result, last RX revision, pending/uncertain state; never keys.

`RADIOV3 PROVISION END ...` ends permission, drains/records uncertain intents; does not erase persistent context or retire A7's association. Reboot erases volatile session authority. Reopen requires INFO and explicit new session/resume against durable host record; stale boot/session TX always rejects. Host disconnection suspends new TX until explicit rebind; already handed hardware TX may finish and is uncertain if its result is lost. Counter leases are burned regardless.

RX: `RADIOV3 RX boot=... session=... revision=... channel=... timestamp=... mac=<hex> fcs_ok=... rssi=... lqi=...`. Preserve wire encrypted bytes, strip/declare FCS convention, bounded immutable queue, count drops/overflow. Host checks addresses, security/MIC/replay/phase. Firmware does not decrypt keys, NWK or APS; no key material crosses USB in plaintext. Automatic MAC ACK applies only to bound addressed AR1 traffic, not foreign controllers/PANs. Driver has one configured extended address; sequential session setup switches it while radio is safely idle. This handling is a future implementation requirement, not hardware evidence.

## Proposed permission classes — incomplete allowlist

| Phase / class | Captured MAC form | Restriction / evidence |
|---|---|---|
| SCANNING / BEACON_REQUEST | no outgoing fixture | currently blocked; do not infer shape from examples |
| TARGET_SELECTED / ASSOCIATION_REQUEST | C823, command01, capability80, srcIEEE/PANFFFF, dstshort0000/PANtarget, AR1 | physical end-device role only; no router toggle |
| ASSOCIATION_SENT / DATA_REQUEST_EXT | C863, command04, captured140 | compressed target PAN, exact bound rawIEEE, destination coordinator, phase budget |
| ASSOCIATED / DATA_REQUEST_SHORT | captured short/short form from145+, actual FCF in fixtures/index | source assigned short, session PAN, peer0000, command04 only |
| KEY_INSTALLED / DEVICE_ANNOUNCE | 8861, DATA, src assigned short ->0000, AR1; encrypted NWK | only after host durable key+FC reservation; host must validate secured ZDO0013 envelope |
| MANAGEMENT_PENDING / END_DEVICE_TIMEOUT, NODE_DESCRIPTOR, REQUEST_KEY, VERIFY_KEY | observed158/161/174/181 | **blocked until necessity and phase policy are specified/tested** |
| any / PERMIT_JOIN | observed206 | blocked; no propagation of admission expansion |
| any / APPLICATION_DATA, TYPE07, arbitrary encrypted DATA | none permitted | reject |

Device Announce cannot be identified solely by encrypted MAC DATA shape. The firmware can enforce address/length/visible NWK type and phase quota but cannot verify an encrypted APS/ZDO cluster without a key. Do not claim that checking FCF proves the packet is Device Announce. A reviewed host lease/intention plus phase quota provides a trusted-host contract; if adversarial-host enforcement is required, the opaque-firmware design is insufficient and must change. Current prep therefore implements no such permission.

Budget proposal: one association intent per explicit attempt; no automatic association retry; one announce intent per durable reservation; no arbitrary DATA permission at JOINED. Narrow bounded Data Request polling needs timing validation; present proposal supplies no RF polling rate/default. ACK timeout/RX priority must preserve the copied Nordic driver policy. Firmware production TX after provisioning is a separate future ownership contract; RADIOV2's unconditional `ownership_unproven` remains untouched.

## Host implementation contract

`commissioning.py`: input validated beacon/MAC association/security/management events, durable generation and explicit operator intent; output typed phase-limited intent or STOP reason. Never accepts cached response from another attempt. Mandatory predicates: exact IEEE/PAN/coordinator, MIC valid, monotonic per-source/layer replay floor, expected command/type/destination, state revision newer than attempt. Temporary TC key and newly delivered TC key have distinct epochs/counter domains.

`provisioning_store.py`: allocate identity once, lock context, atomic durable key-reference+epoch update, monotonic FC lease allocation, independent NWK/APS security floors and sequence spaces, metadata/generation/attempt journal. Reserve before encryption/handoff. Do not infer ownership from MAC ACK. Incomplete/lost store rejects resume; no reset-to-zero shortcut.

`RadioV3ProvisioningTransport`: no crypto; validate boot/session/generation/ID, copy bytes, correlate local completion and RX independently, surface loss/overflow/timeout/uncertainty; no automatic retries. Interfaces must distinguish local MAC acceptance, authenticated key receipt and fully validated commissioning.

Two PANs: independently provision ctx0 then ctx1 on channel21, with distinct stable IEEE, short assignments, secret refs, key epochs, outgoing leases and replay floors. Later channel/filter scheduling is a separate milestone. AirControls stay paired; count/admission failures STOP without impersonation. Until overall A, next work remains offline; no new-identity hardware gate is authorized.
