# Dedicated RAW identity commissioning V1 — offline preparation

2026-10-06. **B — DEDICATED IDENTITY VALID, COMMISSIONING PARTIAL.**

Counter ownership verdict **A: distinct RAW identities remove the V17 counter-handoff requirement.** This is an architectural result, not a successful new-device join. No firmware/HEX was created: the minimum required commissioning frame set for a fresh identity is not established. No dongle, serial, USB, flash, RF, pairing, MQTT or HA access occurred.

## Identity feasibility and allocation

Read-only local source anchors, relative to the workspace:

| Source | Observation |
|---|---|
| `nrf sdk/external/nRF-IEEE-802.15.4-radio-driver/src/nrf_802154.h:195` | setter accepts eight bytes, little endian |
| same directory `nrf_802154.c:174` | `nrf_802154_extended_address_set` delegates to PIB |
| `nrf_802154_pib.c:54–67,203–210` | one static PIB, one eight-byte extended address, setter copies bytes |
| `nrf sdk/external/zboss/include/zboss_api.h:762` | public `zb_set_long_address` exists |
| `firmware/airnanny_v17/main_airnanny_min.c:2029–2033` | `ZB_INIT`, read hardware EUI via `zb_osif_get_ieee_eui64`, then set address before startup/join |
| `host/airnanny2mqtt/src/airnanny/security.py` | nonce is source IEEE LE8 + FC LE4 + effective control 0x2D; PAN is absent |

A software-selected address is technically supported. For a temporary ZBOSS image the observed application initialization point is after `ZB_INIT`, before stack startup/join. This does not prove override precedence when pre-existing NVRAM is loaded; an isolated new commissioning record would be necessary. V17 remains unchanged and retains its hardware identity. No proprietary ZBOSS binary disassembly was used.

IEEE distinguishes universal EUI assignment from locally administered MAC addresses. For local individual addresses the canonical initial octet has I/G=0, U/L=1; the administrator must ensure uniqueness within the span of use. A random local address must not be represented as an allocated universal EUI. See [IEEE RA guidance](https://standards-support.ieee.org/hc/en-us/articles/4888705676564-Guidelines-for-Use-of-Extended-Unique-Identifier-EUI-Organizationally-Unique-Identifier-OUI-and-Company-ID-CID). These MAC allocation rules do not establish A7 admission or Zigbee conformance for local identifiers. Use allocated universal EUI-64 values for a conformance requirement; use administrative local addresses only under an explicitly reviewed experimental policy.

Future allocation: create `raw_ctx0_ieee` and `raw_ctx1_ieee` once, persist before BEGIN, compare against both AirControls, coordinators, V17 and all local records; reject duplicates, zero/all-ones and group addresses. Persist the allocation policy. Canonical big-endian text and eight-byte LE wire representation must be explicit. No real RAW identities are assigned by this audit. Never regenerate at reboot or copy a captured AirControl address/short.

One driver address can represent one commissioning session at a time. ctx0/ctx1 provisioning is sequential. A later dual-PAN runtime needs deliberate switching/filtering; this report does not establish simultaneous native address support.

If two PANs have equal NWK keys, same source IEEE, same independently allocated FC and same effective control, they have the same CCM nonce. PAN separation does not prevent nonce reuse. Distinct source IEEE makes those nonces different even with equal keys and FC. The offline checks follow the read-only Python codec layout. Each RAW context has independent durable ownership and replay floors; key-sequence alone is not a key epoch identifier.

## Scope of capture evidence

All 17 pcaps were scanned; file hashes/counts are in `evidence/capture_inventory.json`. Exactly one association request/response pair was found: `airnanny_pairing.pcapng` frames 138/142. It belongs to physical AirControl **00124b00369c711f**, not V17, on channel21/PAN FA9B, coordinator/TC **00124b0036a148e5**, coordinator short0000. Existing C9B7 traffic precedes association; this is not evidence of a never-used identity. No V17 association fixture or first-ever zero-based security-counter fixture exists in this dataset.

`evidence/commissioning_frames.json` records 79 selected frames with capture/frame/time, wire MAC bytes (without FCS), explicit non-secret MAC/NWK/APS fields. Absent fields mean absent/not exposed, not zero. Nested security layers must be distinguished using `offline_test_result.json`; flattened tshark fields alone cannot distinguish outer NWK and inner APS counters. `CAPTURE_SEQUENCE.md` is the per-frame index. `fixtures/pairing.json` contains 13 deterministic wire fixtures including both key exchanges. No Transport Key plaintext/key material is committed.

## Observed sequence

All frame references below are `airnanny_pairing.pcapng`.

| Frames | Observed step | Implication |
|---|---|---|
| 99,137 | coordinator beacon, PAN FA9B; 136 permit-join request precedes 137 | discovery/admission observable; no raw-origin beacon-request fixture found |
| 138,139 | association request + same-DSN ACK | AirControl requests assigned address |
| 140,141 | extended-source MAC Data Request + ACK | polling retrieves indirect response |
| 142,143 | association response + ACK | assigned C9B7, status00 |
| 145–153 | MAC polls; application status also appears | receiving an application frame is not key installation confirmation |
| 154,155 | first APS Transport Key + MAC ACK | authenticated NWK-key delivery |
| 156,157 | secured Device Announce + MAC ACK | first observed outgoing secured management frame |
| 158,159 | End Device Timeout Request + ACK | additional role/liveness negotiation |
| 160 | coordinator relays Device Announce | corroboration, not durable host ownership proof |
| 161,162 | Node Descriptor Request + ACK | more management, necessity for raw identity unresolved |
| 166–173 | polls, timeout response168, node descriptor response172 | responses delivered indirectly |
| 174,175 | APS Request Key + ACK | requests TC link key, not a second NWK key |
| 177–180 | poll, second Transport Key179, ACK | TC link-key update exchange |
| 181,182 | Verify Key + ACK | new-link-key hash verified offline |
| 183–203 | polls/application/other-PAN interleaving | do not equate capture adjacency with causal obligation |
| 204,205 | APS Confirm Key SUCCESS + ACK | authenticated success for observed link-key update |
| 206–208 | Permit Join Request and relay | do not automatically reproduce permit-join expansion |

Association Request wire: `23c81e9bfa0000ffff1f719c36004b12000180`.
FCF C823, command frame/version0, AR1, PAN compression0, destination mode2/FA9B/0000, source mode3/PAN FFFF/IEEE00124b00369c711f, DSN1E, command01, capability80.

Capability80: alternate coordinator0, device type0 (RFD/end device), power source0, receiver-on-idle0, security capability0, allocate-address1; reserved bits3/6 are zero. Security-capability0 does not imply that subsequent NWK traffic is unsecured. Device Announce repeats capability80. The accepted captured role is a polling end device, not a router. This is the sole evidenced candidate role. Router capability from the V17 application configuration cannot be substituted for a captured successful association.

Response wire: `63ccd49bfa1f719c36004b1200e548a136004b120002b7c900`.
FCF CC63, command/version0, AR1, compression1, destination/source extended; PAN FA9B shared, DSN D4; command02, assigned C9B7, status00. ACK frame143 corroborates delivery. Parser and typed request/response builders reproduce both captured frames exactly. New provisioning replaces addresses/DSN with allocated/session values, never copies historical C9B7 as its own short.

## Commissioning security — authenticated offline

Independent AESCCM verification used an in-memory historical TC key from local Wireshark configuration, selected by successful MIC, without exporting it. Repeat runs may use `AIRNANNY_HISTORICAL_TC_LINK_KEY`; fixtures carry ciphertext only. Missing secret is explicitly reported as unverified. No key is an input argument visible in process command lines.

The captured subset uses AES-MMO keyed hash for transport derivation and AES-CCM MIC32. Effective low security-level bits are patched to5 for nonce/AAD while wire controls retain their captured values. Derivation selectors00/02 and this patch are corroborated by [Wireshark security source](https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-zbee-security.c). The code implements the small observed subset; it does not claim general APS support.

| Frame/layer | Wire/effective control | Key and derivation | FC | AAD boundary |
|---|---|---|---|---|
| 154 APS | 30/35, key-id2, extended source | keyed AES-MMO(TC link key,00) | 0 | APS `2168` + patched aux13 |
| 156 and other NWK | 28/2D, key-id1 | delivered NWK key directly | 419511 for156 | complete NWK header + patched aux14 including keyseq0 |
| 174 inner APS | 20/25, key-id0 | historical TC link key directly | captured in test evidence | APS header2 + aux13; plaintext0804 |
| 179 outer NWK | 28/2D | delivered NWK key | 1930297 | NWK header8 + aux14 |
| 179 inner APS | 38/3D, key-id3 | keyed AES-MMO(historical TC link key,02) | 1 | APS `216A` + aux13 |
| 204 outer NWK | 28/2D | NWK key | 1930300 | NWK header8 + aux14 |
| 204 inner APS | 20/25 | newly delivered TC link key | 2 | APS `216D` + aux13 |

For each layer nonce = security-source IEEE LE8 || security FC LE4 || effective control1. NWK/PAN headers are not included in an APS nonce; APS AAD excludes outer NWK/MAC headers. APS controls30/38/20 do not carry a network-key sequence octet in their aux13. NWK control28 aux14 does. Source for154/179/204 is TC00124b0036a148e5. MIC length4. Complete nonce and non-secret AAD bytes are in test evidence.

154: NWK FCF0048, unsecured NWK DATA, NWK dstC9B7/src0000/radius60/seq177; MAC8861, 0000->C9B7, AR1. APS command FCF21/counter104; encrypted plaintext35 = command05, key-type01, secret16, keyseq00, destination IEEE00124b00369c711f, TC IEEE00124b0036a148e5. Returned secret is used only in memory to authenticate NWK frames. It is not logged, hashed into a public fingerprint or serialized.

179: NWK-secured frame contains APS-secured Transport Key plaintext34 = command05, key-type04 (TC link key), secret16, destination IEEE, TC IEEE; no delivered NWK keyseq. Its outer/inner layers both authenticate and reencrypt exactly. 174 decrypts to Request Key0804. 181 is APS command0F/key-type04, device IEEE, hash16; that hash equals keyed AES-MMO(new TC link key,03). 204 decrypts/authenticates with the newly delivered TC key to Confirm Key10/status00/type04/deviceIEEE (length11). Hash/key bytes are deliberately omitted from exported plaintext.

This is stronger than trusting tshark's command label. All 12 checked security layers authenticate and recreate the original ciphertext/MIC. Deliberately corrupted APS and NWK MICs are rejected. It still does not establish which post-announce exchanges a new A7 admission requires or what omission is safe.

## First observed Device Announce

Frame156: MAC FCF8861, DSN23, PANFA9B, srcC9B7 -> next-hop0000, AR1. NWK FCF0208, dstFFFD/srcC9B7/radius60/seqF6, security source00124b00369c711f, FC419511, keyseq0. APS plaintext `080013000000000100b7c91f719c36004b120080`: APS data/control08, endpoint0, cluster0013/profile0000, sourceEP0, APS counter1; ZDO TSN0, shortC9B7, IEEE, capability80.

419511 is the first secured outgoing counter **observed after this association**, not the first counter ever used by this IEEE/key pair. It must never become a default or a copied counter seed for a RAW identity. A newly allocated identity gets a durable owner before its first secured management TX; initial counter policy must be specified and tested independently, not guessed from this rejoin.

## Ownership alternatives and remaining blockers

Option A: temporary ZBOSS with fresh RAW IEEE can call the address setter, but it consumes secured management counters during commissioning. Safe one-way transfer still requires a proven upper bound/reservation, stopped ZBOSS and durable export before raw starts. Public NIB snapshots alone do not prove next/safe counters or APS counter domains. The earlier RADIOV2 handoff limitation remains applicable to this temporary image. Not selected as ready.

Option B: direct raw host owns identity and every NWK/APS counter from the first secured transmission. The association and Transport Key forms are reproducible; this is the preferred design direction. **Not ready yet:** only re-association of a pre-existing physical controller is captured; no fresh-identity admission evidence; timeout/poll/admission limits and necessity of the observed timeout/descriptor/link-key/permit-join follow-ups are not established. Beacon request TX is absent. No complete host state machine or firmware phase allowlist is implemented/tested. A7 device-count/local-address acceptance is unknown. These are partial evidence/implementation boundaries, not proof that a vendor stack is indispensable.

Distinct RAW IEEE separates outgoing nonce/replay domains from V17. V17 never uses RAW IEEE; raw never uses V17 IEEE. This eliminates import-back into V17. It does not remove incoming A7 replay state, shared physical radio scheduling, A7 admission limits or cross-PAN nonce collisions if identities were incorrectly reused.

## Host state and crash model

Proposed interfaces for the separate Python implementation: `commissioning.py` consumes typed validated RX/session events and returns phase-limited TX intents; `provisioning_store.py` atomically reserves counters and stores authenticated keys via secret references; `RadioV3ProvisioningTransport` binds intents to boot/session/phase and emits immutable results. No production Python files are changed here.

All timeouts below are **proposed fail-stop budgets, not captured timing requirements**. No automatic association/control retry. Bounded polls may repeat only with explicit phase-specific budget after future validation. Local MAC completion/ACK is not join confirmation.

| State -> next | Required input / action | Budget and persistence/crash rule |
|---|---|---|
| IDLE -> SCANNING | explicit operator start, allocate/check stable identity | persist allocation before any TX; scan30s proposed; current prep read-only |
| SCANNING -> TARGET_SELECTED | observed beacon, operator selects exact PAN/extPAN/coordinator/channel | persist binding; reject changed target; no blind permit-join TX |
| TARGET_SELECTED -> ASSOCIATION_SENT | exact association intent, persist attempt before handoff | proposed10s; ambiguous TX causes STOP/manual restart, no retry |
| ASSOCIATION_SENT -> ASSOCIATED | addressed association response status0, assigned valid unicast short | persist short/generation; failure/address collision => STOP |
| ASSOCIATED -> WAIT_TRANSPORT_KEY | validated polling plan | proposed30s; no key guessing; restart partial association requires explicit reconciliation or retire identity |
| WAIT_TRANSPORT_KEY -> KEY_INSTALLED | MIC-valid type01 Transport Key, exact session destination/TC | atomically save secret ref, key epoch, replay floors, counters; no announce before durable save |
| KEY_INSTALLED -> DEVICE_ANNOUNCE_SENT | reserve FC, write high-water, encrypt captured-shape announce | persist reservation+intent before firmware handoff; proposed10s; uncertain TX burns FC |
| DEVICE_ANNOUNCE_SENT -> MANAGEMENT_PENDING | successful local TX plus independently validated management response | observed follow-ups need explicit substates; cannot declare JOINED merely on ACK |
| MANAGEMENT_PENDING -> JOINED_RAW | validated required timeout/link-key verification/confirm/admission policy | **blocked predicate** until complete minimal subset defined/tested; key delivery alone insufficient |
| JOINED_RAW -> APPLICATION_SYNC_REQUIRED | persist sole raw ownership | NO TYPE07; separate authorized application synchronization milestone |

The observed link update would need explicit REQUEST_TC_KEY -> WAIT_TC_KEY -> VERIFY_KEY_SENT -> WAIT_CONFIRM_KEY subphases, NWK and APS replay floors/counter leases, secret replacement with crash-safe generations, and authenticated SUCCESS. This draft deliberately does not silently skip them or claim they are obligatory in every join.

Persistence: local ignored `.local/ctx0.json` / `.local/ctx1.json`, validated by `provisioning_record.schema.json`, atomic replacement plus durable file/directory flush as supported by target platform, single-writer lock and rollback detection. Secrets live in an ignored protected secret store; public record carries references only. Record MAC/NWK/APS/ZDO counters, key material domain/epoch and inbound per-source/per-layer floors separately. Security counter high-water is exclusive next-safe bound, never decreases, exhaustion fails closed. Never reset because short/PAN/sequence changes. With equal secret bytes the same source nonce domain must still be tracked across logical key epochs. Restore old backups only after retiring the old identity/domain; otherwise STOP.

| Crash point | Safe action |
|---|---|
| association response, before key | retain assigned short/attempt; no secured TX; reconcile explicitly or retire identity |
| received key, before durable save | no TX allowed; restart cannot pretend KEY_INSTALLED; obtain authenticated redelivery under reviewed flow or retire |
| saved key, before announce | resume only with same durable generation/epoch/replay state, new lease |
| after counter reservation | burn reserved FC even if frame never reached firmware |
| handed encrypted announce, result unknown | burn FC; do not replay same security-counter payload; STOP/reconcile |
| MAC ACK, before host outcome save | durable lease already exists; burn FC, ACK is not commission success |
| after validated join | save JOINED_RAW before application use; reconnect with new session, preserve all floors/leases |
| partial restart / lost secret / stale backup | no guessed rollback; explicit identity retirement/reprovision or validated durable continuation |

Retirement does not delete A7-side associations and cannot guarantee capacity. A fresh identity must be allocated rather than reusing an uncertain nonce domain. Physical AirControl remains paired; admission failure is a finding, never a reason for impersonation.

## Firmware boundary and tests

RADIOV2 ownership gate remains always false. No changes to raw_radio_v2, V17, old gate, installed SDK or Python. New `identity_commissioning_v1` is an offline audit/codec/spec directory, **not** the conditional `raw_radio_v3_provisioning` firmware experiment. Firmware build/test totals0; HEX absent/unflashed. Draft [RADIOV3 protocol](RADIOV3_PROVISIONING_PROTOCOL.md) is non-executable and fail-closed.

Actual offline results: 79 MAC parse/serialize roundtrips; 2 association field checks; 2 typed association builders exact; 8 invalid-input rejection checks; 12 authenticated security-layer exact reencrypt checks; 2 tampered-MIC rejections; Verify Key hash match; 2 nonce-domain checks. Reproducer: Python with cryptography, `run_offline.py --local-wireshark-key-oracle` or environment secret. The explicit local oracle option is for historical capture testing only; future provisioning must use explicit scoped secret references, never auto-try a production key ring.

## Next gate / STOP

Before declaring A: complete/testing of fresh-identity discovery/management subset, address policy/admission assumptions, end-device polling and post-key update phases, durable store/counter domain checks, and firmware provisioning allowlist. Do not solve missing evidence by permitting arbitrary encrypted DATA. If future offline work reaches A, separately authorize **SINGLE-PAN FRESH RAW IDENTITY PROVISIONING**, keeping physical AirControl paired and V17 identity untouched. Acceptance: new short assigned, key authenticated and durable, required secured management complete, both existing controller/reference identities intact. No TYPE07 until that passes. This milestone stops with B and authorizes no hardware action.
