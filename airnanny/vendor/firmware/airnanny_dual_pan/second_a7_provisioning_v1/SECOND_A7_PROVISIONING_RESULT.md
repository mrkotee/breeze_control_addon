# Issue #4 — PASS, final recovery verified

Independent ctx1 for A7 в спальне (PAN0B7A/channel21/RAW027a56bb75a41437) has completed commissioning, retained-key secured rejoin, Announce, authenticated Timeout and60s normal readiness. V25 guard9754e7c3a9e54347b9ad51695d783ab2 sent exactly one adjacent FAN command; fresh correlated A7 status confirmed it. All72 accepted transmissions have successful terminal results; END72/72 clean, no pending/drop/quarantine. No pairing-button hold was used in this final session.

The operator restored V17 and confirmed both A7/controller pairs healthy. INFO verified V17, with zero RF during recovery inspection. Guard FINISHED/confirmedtrue; the final durable recovery state is FIRST_TYPE07_CONFIRMED. Generation16/contextgeneration14, next outgoingFC1088 and all incoming floors retained; original independent key/identity unchanged. All354 protected ctx0/source/security files are unchanged.20 offline checks cover real C dispatcher, bounded RX admission and replay/isolation negatives. Final closure changed only the expected recovery flags. AcceptancePASStrue. No further manual action is required; automation has not been restarted.

The fixes distinguish protected rejoin from initial association, remove the unnecessary permit/hold gate for retained-key recovery, wait within the existing20ms admission bound while RX/immediateACK is busy before one driver submission, and discard exact copies of already authenticated/ignored foreign traffic without readiness or command credit. Existing crypto/replay protection for RAW-addressed frames, durable counter leases,60s readiness and one-FAN/no-retry policy remain. Normal-mode rejoin is now demonstrated on the real A7.

Final evidence: `evidence/second_a7_provisioning_v1.json`, `../ctx1_rx_admission_v25/hardware_result.json`. Firmware/source details: `../ctx1_rx_admission_v25/README.md`. Earlier attempts below are historical records; their pending/prepared wording describes the state at that time and does not authorize rerunning consumed guards.

## Hardware FAN confirmed; final V17/physical recovery pending

V25 guard9754e7c3a9e54347b9ad51695d783ab2 passed normal-mode secured rejoin, Announce and Timeout with two authenticated parent proofs; no pairing-bodybutton hold. Original60s readiness completed with53 ACK polls, zero CCA skips, success in every10s interval. Exactly one adjacent FAN was transmitted and confirmed by fresh correlated A7 status. All72 accepted transmissions have successful terminal results, END clean72/72 with no pending/drop/quarantine. RX admission deferred213 main-loop observations before submission, within unchanged deadlines. No retries of submitted secured/application frames. Retained independent key, identity and replay floors; generation16/contextgen14/nextFC1088/short6C55. All354 protected files unchanged.

Hardware control is confirmed; final recovery is not yet verified. Operator-only application restore of V17 and separate both-pair health confirmation are the remaining acceptance boundary. Issue4PASS staysfalse until those complete. Evidence: `../ctx1_rx_admission_v25/hardware_result.json`. No automaticflash/reset or automation restart.

## Latest: normal-mode beacon received and rejoin MAC-ACKed; first poll blocked by RX_BUSY

Guard8bc1cb4eeca14cd1a1734e4b214a91a3 received a fresh target beacon without a body-button pairing hold. Secure rejoinFC928 received a MAC ACK. Its first automatic poll failed before RF start, submit_reason4/RX_BUSY, state2/RX. No authenticated rejoin response, parent proof, Announce, Timeout or FAN; do not equate MAC ACK with successful rejoin. END clean3/3 with no pending/drop/quarantine. Gen15/contextgen13 unchanged, new nextFC960 retained. Operator confirms both pairs healthy after the attempt. The secondary END replay fault is an exact repeat of already ignored known-peer foreign group traffic; disposable real-capture replay confirms new handling supplies no proof/baseline/outgoing credit.

V25 performs read-only RX/immediateACK admission before driver submission, keeping the same intent and original20ms queue/response/watchdog bounds. Busy beyond the limit stops without submitting; once idle submits once. Race/APIrejection remains a stop, never retransmission. Exact previously ignored foreign copies are discarded; RAW-addressed replay and unseen stale packets stay rejected.20 offline checks pass actualC plus captured-copy replay; CURRENT and354 protected files unchanged, noCOM/RF. ARMimage compiledSHAf62d6f6536d021ebd488efa1d69d240e03c2de46b86fb9ca44d336faa79a1aa6. Guard9754e7c3a9e54347b9ad51695d783ab2 prepared, not executed; next action manualV25 flash only. No intermediateV17. Issue4PASSfalse. Handoff: `../ctx1_rx_admission_v25/MANUAL_HANDOFF.md`.

## Prepared: normal-mode retained-key rejoin, no pairing button

Both pairs are explicitly confirmed healthy after V24 guard12cbd05cbcee436da4804845ea9ce07a; sustained blinking during hold confirmed separately. Secure NWK rejoin differs from initial MAC association and does not require Permit Association under the documented Zigbee procedure. Real A7 support is unproven. The new host-only normal-mode scenario retains the installed independent key/identity, gen15/contextgen13/FC928 and all replay floors. It requires fresh authenticated parent baseline and fresh validated target beacon, retains max3 bounded discovery requests, one secured rejoin/Announce/Timeout,60s readiness and unchanged one-FAN/fresh-confirmation/no-retry checks. No A7 hold, release marker or release sound is fabricated.

Fifteen offline actual-C checks pass with closed-network beacons and no permit packets, including missing witness, wrongPAN, failed localTX, lost beacons, powerON wait, missing appconfirmation and six isolation negatives. CURRENT/354 protected files unchanged, noCOM/RF. Same installedV24. Guard8bc1cb4eeca14cd1a1734e4b214a91a3 prepared but not executed; next action is operator USB disconnect/reconnect only, then one physical FAN cue. No intermediateV17. Issue4PASSfalse. Handoff: `../ctx1_normal_rejoin_v24/MANUAL_HANDOFF.md`.

## Latest hardware result: no pairing permit, zero radio transmissions

V24 guard12cbd05cbcee436da4804845ea9ce07a was manually flashed and executed. Physical controller TYPE07 and matching A7 status were captured. During the180s pairing window the operator confirmed holding the body button, but no authenticated pairing permit arrived. The process stopped with `no_fresh_authenticated_pairing_permit_NO_TX`; the operator then confirmed release. No BIND, discovery scan, secured TX, FAN or outgoing counter lease occurred. The new three-scan feature was not reached.

Offline DPAPI audit found515 contiguous RX records,134 authenticated ctx1 frames and82 authenticated TC frames; zero permit-cluster candidates or offline accepted permits. The same key/decoder/observer recognizes the earlier known-successful capture. END has accepted/terminal0/0, pending0, drops0/0, quarantine0 and ownerfree. Security gen15/contextgen13/nextFC928 retained; all354 protected files unchanged. No intermediateV17 is requested. New full health confirmation and observed blinking behaviour are pending. No identical retry is prepared; issue4PASSfalse. Evidence: `../ctx1_discovery_retry_v24/hardware_result.json`.

## Latest: one missed discovery beacon; V24 bounded scans prepared

Guard80b15ca5b8b941caa86029dc5933c6dd got freshauthenticatedpermit/status, transmittedonebeaconrequest, receivednobeacon, andendedclean1/1withoutsecuredrejoin/FAN. NoCRC in scanwindow. Operatorreleasedafterstop. No key/outgoingcounterchange; gen15/FC928/floorspreserved. Causeunknown.

Newguard12cbd05cbcee436da4804845ea9ce07a prepared for manuallyinstalledV24: atmost3locallysuccessfulbeaconrequests withdistinctpersistedDSNs/freshRXwindows. Thirdmissstops; failedlocalTX neverretried; secured/appcommands remainnoretry. Sixteenofflinechecks pass actualnativeC loss1/2thenfullcontrol,loss3zero secured/appcounterlease/FAN, and power/audio/isolationcases. CURRENT/354protectedunchanged; noCOM/RF/audio. BuildhexSHA0f699fa9512e6248ee49288d703f2c77e36d8e59f229d8fcde5d901a0ebbba3b. Handoff: `../ctx1_discovery_retry_v24/MANUAL_HANDOFF.md`. NoV17intermediate. Issue4PASSfalse.

## Prepared: physical ON wait after joining, sameV23

Operator confirms the A7bodybutton was used and immediately releasedonsound. After reportedOFF, operator confirms restoringON. Newguard80b15ca5b8b941caa86029dc5933c6dd waits for physicalON andfreshmatchingstatus ifOFF occurs afterparentsetup/readiness, before unchangedconservativeFANpreflight. It never sends a powercommand. SameV23 image; nextmanualUSBboot only, noV17. Twelveofflinechecks pass, including actualnativeC physicalONafter50s/oneconfirmedFAN,missingONzeroFAN/lease andmissingconfirmationnoretry. Currentgen15/FC928/replayfloors and354protectedfiles unchanged. Issue4PASSfalse. Handoff: `../ctx1_postpair_power_v23/MANUAL_HANDOFF.md`.

## Latest: release confirmed; full60s readiness passed; FAN blocked while power OFF

Guard5c2dd9f07e574ccdb6e096a5f5ed200a authenticated parent setup, played the local release cue and recorded the operator release. Normal-mode readiness lasted60s with54 successful ACK polls. At application preflight, conservative_FAN_state_required stopped before any application intent/counter lease or FAN. All91 RF transmissions terminated successfully, END clean with no drops/quarantine. Preserve gen15/FC928 and advanced replay floors. Protected354 files unchanged.

The operator reported the bedroom A7 powered off. Authenticated TYPE07 from the known bedroom physical controller at revision421/radio137939696us/FC837220 carries power0; matching TC TYPE06 at revision431/FC2487010 reports power0. Dongle TYPE07 count0, no application intent. Do not attribute the power-off to a dongle FAN or claim its physical cause is established. Return the device to intended operation via the physical controller before more application checks. No V17 request is justified solely by this clean result. Issue4PASSfalse. Evidence: `../ctx1_release_audio_v23/power_state_audit.json`.

Earlier recorded results follow.

## Current result: V23 parent setup passed; first idle NO_ACK before chat release

Guard6e386147e7bf4c5b86364c9dadb29995 authenticated rejoin/Timeout and completed Announce. Its first ordinary poll failed NO_ACK1.125s after release signalling, before the chat could deliver that cue. This is not a release-confirmation timeout. No FAN was sent. END clean10accepted/10terminal, no drops/quarantine. Gen14/contextgen12/FC832 and advanced incoming floors retained. All354 protected files unchanged. Operator subsequently released the button and explicitly confirmed both pairs healthy. RF cause not established.

New guard5c2dd9f07e574ccdb6e096a5f5ed200a is prepared with same installedV23, immediate local350ms sound cue after parent activation and before first poll. This tests prompt release independent of chat delivery; the180s report window and60s normal-mode readiness remain, with oneFAN/no retry. Ten offline tests pass, including actual native C signal ordering/full60s/single confirmedFAN and six isolation domains. No actual sound/COM/RF offline. Manual USB reconnect is next; no reflash or V17. Handoff: `../ctx1_release_audio_v23/MANUAL_HANDOFF.md`. Issue4PASSfalse.

Earlier results follow.

## Prepared continuation: V23 chat budget; manual flash required

The operator explicitly authorizes proceeding without intermediate V17 restoration. New exclusive guard `6e386147e7bf4c5b86364c9dadb29995` is prepared but not executed. V23 provides360s firmware/host session and400 total polls, with a180s release confirmation window, unchanged60s normal-mode readiness, one adjacent FAN and no retry. All50 offline checks pass, including native C delays50/165s and successful single-FAN confirmation,360s stop,400-poll count bound, missing release/status/confirmation, and CURRENT isolation. CURRENT and354 protected files remain unchanged. NoCOM opened orRF transmitted. Manual application-only installation of `../ctx1_held_budget_v23/releases/airnanny_ctx1_held_budget_v23.hex` is the next boundary. Issue4 PASS remains false. Full continuation instructions: `../ctx1_held_budget_v23/MANUAL_HANDOFF.md`.

## Current result: held parent setup confirmed; release handoff timed out

Guard `385224c0bdec45a4903af89e46d58ce3` authenticated rejoin and Timeout, completed Announce and installed the current short while the operator held the bedroom A7 button. Parent became active. The host exhausted its 30-second release confirmation window before the reply could be recorded. No dongle FAN was sent. The operator subsequently reported releasing the button.

Generation 13, next FC 736 and advanced replay floors are retained. Clean STOPPED END with all RF terminal and no pending TX, drops or quarantine. Protected ctx0 inventory unchanged. Manual V17 recovery and physical health verification pending. Issue #4 PASS false. Before another pairing action, fix the chat handoff budget together with the firmware 120-second session cap. Evidence: `../ctx1_held_refresh_v22/hardware_result.json`.

Earlier recorded results follow.

## Latest verified attempt: physical input captured, discovery received no beacon

Guard `f1a3dd8b6835422086becc8749084eae` is FINISHED with V17 verified by INFO and the operator reply `готово` to the restoration/health request. This closes the deferred restoration of the preceding zero-TX passive timeout without changing its sealed evidence.

The bedroom controller TYPE07 and matching authenticated A7 TYPE06 were captured before pairing. The bedroom A7 authenticated permit was then received. One beacon request completed locally, but the entire capture contains zero beacon frames; this is not a beacon parser rejection or a late manual FAN response. Application TYPE07 was never sent. Generation remains 12 and next outgoing counter 608; updated incoming replay floors are preserved. Radio END has no pending TX, drops or quarantine.

Offline comparison found beacon responses in all six earlier ctx1 scans, using the same request layout except DSN. Local TX completion does not prove reception by A7, and this capture cannot establish why the response was absent. No speculative key change, replay rollback, automatic retransmission or duplicate guard execution was performed. Issue #4 acceptance remains false. Evidence: `../ctx1_prejoin_retry_v22/scan_audit.json`, `scan_history.json`, `recovery_closure.json`.

# Latest attempt: passive wait timeout; recovery pending

No physical TYPE07 was registered in180s. No BIND or RF transmission.
Gen12/FC608 retained; clean zero-TX END. Manual V17 restoration pending.
No next hardware attempt is prepared. At future manual cues, the assistant
should yield the turn promptly so the operator can act before the deadline.

# Issue #4 — passive controller proven; operator ordering corrected

State: **PREJOIN_BASELINE_FLOW_REVIEWED_MANUAL_FLASH_REQUIRED**.
Issue4 PASS remains false. Passive diagnosis authenticated bedroom peer
TYPE07 at164.499s and matching TC TYPE06 at167.676s, with zero dongle RF.
A25s chat-mediated baseline window does not accommodate this observed
human timing. Earlier RF losses remain separate unresolved observations.

New flow captures physical FAN/opaque bytes before BIND, then awaits fresh
A7 permit. Only after retained rejoin/Announce/Timeout and60s readiness
may the same-boot witness be attached to the current context. Attachment
forces a NEW matching post-readiness TYPE06; the pre-rejoin status cannot
authorize TX. Changed epoch/key/RAW/PAN/short/boot/generation rejects the
witness. Latest original physical bytes are retained exactly, with all
later physical commands and replay floors observed throughout the session.
At most one adjacent FAN and fresh correlated confirmation, no retry.

20 tests pass: native C165s manual delay/full control, missing fresh status
zero FAN/no application counter lease, missing confirmation/no retry,
opaque byte retention, command2 replay floor advancement and6 CURRENT
isolation domains. Firmware/protocol limits and ctx0 remain unchanged.
V17 and both pairs healthy; gen12/ctxgen10/FC608 retained.

Guard 6898e0d8b24843c3a2b859d61187dc49 awaits manual reinstall of the same +8dBm image.
Both manual actions occur before the bounded active session.

## Earlier management history

Read-only NO_ACK analysis authenticated the target coordinator's traffic at
RSSIв€’81..в€’78dBm/LQI48..56, and the known original peer atв€’75dBm/LQI72.
The poll envelope matches PAN0B7A/parent0000/current short6C55. The ACK trace
shows one on-air poll and no ACK address detection. Neither eviction nor RF
link asymmetry is proven. A [separate placement measurement](../ctx1_management_placement/README.md)
is prepared, with10 passing admission/negative checks, the same45-case-reviewed
V22 image and an unchanged installed epoch. It requires actual manual placement
change and manual flashing before any device access. No old guard is reused,
no context reset/reassociation occurs, and no application readiness is claimed.

A separately reviewed continuation was executed in
[ctx1_management_cca_v22](../ctx1_management_cca_v22/README.md). It preserves
the minimal management protocol and reuses the proven V22 radio owner and
pre-air CCA acquisition. All45 offline checks passed, including actual C owner
tests for busy-then-idle, four busy acquisitions with zero RF-start, no second
submission after RF-start, END during backoff and acquisition expiry. The
installed ctx1 epoch and all354 protected ctx0 files remain unchanged. The
reviewed new HEX passed its public secret scan and offline preflight. The operator
then flashed it manually. Its one serial session reached the first MAC Poll:
CCA succeeded, RF-start was recorded once, and TXDONE reported `no_ack` with
one ACK timeout. No second submission, timeout request or TYPE07 followed.
NWK next-FC stayed32; END had safe cleanup, owner free and no drops/quarantine.
Manual V17 restoration was verified by one INFO and the operator confirmed both
pairs healthy. Both management guards are now closed. No ACK alone is not
proof of eviction and does not permit resetting retained ctx1 authority.
See [V22 hardware result](../ctx1_management_cca_v22/HARDWARE_RESULT.md).
Management readiness and the required confirmed FAN command remain pending.

The minimal management stage is recorded in
[ctx1_management_v1](../ctx1_management_v1/README.md). Its ARM image and39
offline checks passed, including actual C dispatcher/FakeRadio cases and
launcher ownership checks. All94 radio driver files,354 protected ctx0 files
and the installed ctx1 epoch remain unchanged. The public secret scan passed.
The host admission scope was corrected before hardware and passed40 checks
with the same HEX. The actual management attempt resumed ctx1 and stopped at
the first MAC Poll with `cca_fail`, without retry or timeout. TYPE07 was not
sent; next-FC remains32. END was clean. Manual V17 restoration was verified
through one INFO, and the operator confirmed both pairs healthy. That guard
is permanently closed; management readiness remains unproved. See
[hardware result](../ctx1_management_v1/HARDWARE_RESULT.md).
This stage resumes only the existing ctx1 and allows bounded MAC
polls and at most one End Device Timeout. TYPE07 is locked. Actual management
observations must precede preparation of the subsequent live FAN gate.

The second attempt (`7dd8634f2c1e491d9601be513519583b`) received a fresh
authenticated PAN0B7A permit after the operator enabled pairing on the other A7.
Association status was successful, with current assigned short **6C55**.
Authenticated Transport Key was durably installed in a separate ctx1 epoch
`9985b15dcb574c59b87dc2fb379f317f`. The first outgoing NWK lease was reserved
before encryption; its durable next-FC high-water is **32**.
Device Announce received a local MAC ACK. Exactly six TX accepts and six TX
completions were recorded: one association request, one association extended
poll, three key polls, and one announce. No TYPE07 was sent. END stopped cleanly
with no pending work or RX/output drops. Protected ctx0 files remain unchanged.
The next protocol state is **MANAGEMENT_PENDING**, not application readiness.
The operator manually restored V17 and confirmed both pairs healthy, current
data, no CHECK CASE and no re-pairing. One V17 INFO returned success with zero
RF TX. The second guard is now permanently FINISHED. Read-only post-announce
inspection authenticated the physical controller's current short **F59F** and
recorded no supported NWK Leave in the ten-second window. It does not establish
current live readiness or authorize an application transmission; see
[inspection evidence](evidence/ctx1_post_announce_inspection.json).

The first hardware attempt authenticated the ctx1 baseline, but received no
permit for PAN0B7A. The only permit belonged to PANFA9B; the operator confirmed
pressing the A7 in the second bedroom, previously tested in issue #3.
The attempt stopped before association: zero RF transmissions, no TYPE07,
no installed key epoch and no outgoing NWK counter domain. END completed cleanly.
The operator restored V17 manually; one INFO verified V17, and the operator
confirmed both original pairs healthy, current data, no CHECK CASE or re-pairing.
The first guard is permanently closed.

A separate guard was used for the **other A7, PAN0B7A**. Its entry point is
`retry_after_wrong_pan.py`; it requires the sealed zero-TX outcome and recovery
evidence, unchanged original sources and firmware, and another manual flash.
See [retry review](evidence/wrong_pan_retry_review.json) and
[hardware result](evidence/second_a7_provisioning_v1.json).
The exact original offline review is preserved in
[offline_preparation.json](evidence/offline_preparation.json).
Do not rerun preparation or verification generators after hardware has started.

The new persistent dedicated ctx1 RAW IEEE is **027a56bb75a41437**
(wire little endian `3714a475bb567a02`). Its authoritative allocation is in
ignored `.local/identity/ctx1.json`; the non-secret target binding is
[profile.json](profile.json). Re-running preparation preserves this identity.
Allocation excluded both physical AirControls, both coordinators, V17 reference,
ctx0 RAW IEEE and earlier textual experimental identities (39 exclusions).
The initial allocation is unused: no association attempt, assigned short,
installed Network Key, key epoch or outgoing NWK counter has been invented.

Target: PAN **0B7A**, channel **21**, coordinator short **0000**, coordinator /
security-source IEEE **00124b0036a1875f**. The original physical AirControl is
**00124b0036a18944**; **F59F** is an observation hint, not an authoritative future
short. The controller must retain its pairing.

## Software prepared

The existing V7 commissioning state machine and runner are reused with a narrow
ctx1 target specialization. Protocol, ACK checks, two association-poll limit,
no-gap key-poll scheduling, eight key-poll budget, TC Transport Key predicate,
DPAPI durability and the first 32-counter lease retain their proven behavior.
The new admission accepts an unused allocated identity instead of ctx0's already
associated historical seed. ctx1 secrets, replay floors, epochs, counters and
MAC/NWK/APS/ZDO sequences use separate storage; no ctx0 state is a fallback.
Context and key-epoch anchors reject transplanted metadata before reservations.

This adaptation is necessary because frozen V7 commissioning and V22 recovery
sources explicitly reject ctx1 / PAN0B7A and pin ctx0 identities. See
[prepare.py](prepare.py) and [source provenance](evidence/provenance.json) for
the reproducible changes. Earlier files and security authority remain intact.
This is target adaptation of the existing pipeline, without new reverse
engineering or a new commissioning algorithm.

The V22 FAN adapter is reused through [application_adapter.py](host/application_adapter.py),
bound to a distinct ctx1 epoch/attempt and a current authenticated physical
controller short. Its offline test uses synthetic readiness and keys; it is
not a hardware launcher or membership proof. FAN remains one adjacent step,
one-field mutation, durable FC reservation before encryption, no retry and
fresh correlated TYPE06 confirmation.

## Independently enrolled historical candidates

The ctx1 Network Key candidate passed **53 MIC checks on PAN0B7A captures**
with security source `00124b0036a1875f`, before separate ctx1 DPAPI storage.
Historical replay floors and outgoing counters were not imported.
The TC bootstrap was selected against historical encrypted Transport Key
evidence and stored separately as **UNVERIFIED_ON_CTX1**. It grants no ctx1
TC-link-key state. Actual ctx1 Transport Key MIC and destination/source binding
must pass before a freshly generated independent installed epoch exists.
No key material, plaintext Transport Key, or candidate key fingerprints are public.
See [candidate evidence](evidence/candidate_provenance.json).

## Firmware and checks

Initial commissioning image:
[airnanny_ctx1_commission_v7.hex](releases/airnanny_ctx1_commission_v7.hex).
SHA256: `5A9E612F9BC88E446A691911574169CBE347DA90A2E3A77C24DDD5040E50ADB6`.
ARM build succeeded for nRF52840/PCA10059/MBR, application address `0x1000`.
It was flashed manually for both attempts. Application TX is locked in this image.
V17 restoration after the second attempt is verified.

The final machine-readable evidence and exact test count are in
[second_a7_provisioning_v1.json](evidence/second_a7_provisioning_v1.json).
Offline tests exercise the actual C dispatcher via FakeRadio, protected key
durability failures, monotonic FC burning across restart, guard/USB failures,
V22 FAN build/confirmation, and all six requested negative isolation cases:

| Isolation case | Offline result |
| --- | --- |
| ctx0 key supplied on ctx1, including equal bytes with wrong ownership | rejected |
| ctx0 replay watermark supplied on ctx1 | rejected; floor unchanged |
| ctx0 RAW IEEE supplied on ctx1 | rejected by host and firmware |
| ctx0 short substituted for the response-derived current ctx1 short | rejected |
| ctx0 epoch identifier or generation supplied on ctx1 | rejected before reservation |
| cross-PAN incoming frame routed to ctx1, including equal key bytes | rejected before replay mutation |

The protected predecessor comparison covers **354 files**, including ctx0
CURRENT and its security epoch, without a CURRENT exclusion. All are unchanged.
Public artifacts and HEX passed the secret scan against actual local key-oracle
material. Those offline checks opened no COM and performed no hardware work.
The subsequent first hardware attempt and V17 recovery are recorded above.

## Acceptance remains pending hardware

| Required result | Current evidence |
| --- | --- |
| New stable independent RAW IEEE | allocated and persisted |
| status0 association and current short | PASS; current short 6C55 |
| Authenticated ctx1 Network Key installation | PASS; independent durable ctx1 epoch |
| Independent outgoing NWK FC domain | created; durable high-water 32 |
| Device Announce | PASS; local MAC ACK |
| Minimal required management and readiness | NOT RUN |
| One confirmed FAN TYPE07 | NOT RUN; synthetic adapter test only |
| Original controller and both rooms verified after recovery | both attempts verified; operator confirmed both pairs healthy |
| ctx0 remains unchanged | offline hash comparison passed |

The next boundary is operator physical precheck and manual firmware installation.
Follow [HARDWARE_HANDOFF.md](HARDWARE_HANDOFF.md). The initial gate reaches
MANAGEMENT_PENDING and collects post-announce ciphertext RX. Its real ctx1
short/epoch/attempt and authenticated management result must determine the
next binding. Never use ctx0's frozen V22 launcher, short, epoch, predecessor,
or retry guard for this continuation. If an authenticated Leave requests rejoin,
reuse the reviewed V22 recovery path after binding it to that real ctx1 authority;
otherwise use the required minimal management path. No unconditional rejoin,
second application command, reset or unpairing is authorized by this preparation.

**Both commissioning guards are permanently consumed. V17 is restored. Further
hardware work requires a separately reviewed ctx1 management/application gate
and manual installation of its image. Do not repeat commissioning or reuse a
historical readiness observation.**

## Retained ctx1 recovery continuation

The placement guard is FINISHED. V17 INFO and both-pair health are verified.
A correct poll ACK preceded authenticated TC Leave FC2462210/options0x60.
The existing ctx1 epoch retains its blocker, replay floors and nextFC32.
The separately reviewed `ctx1_rejoin_control_v22` stage prepares retained-key
rejoin, fresh readiness and one FAN. Its image requires manual installation.
Issue4 PASS remains false until live confirmation, recovery and isolation
acceptance are complete.

## ctx1 rejoin and Timeout hardware proof

Run99f3b322b8f64c1fb2009345cfc7cdda proved retained-key rejoin/status0,
current-short commit6C55/gen7, Announce ACK and authenticated Timeout.
Readiness stopped on a single on-air NO_ACK before FAN; nextFC128 is retained.
V17 and both-pair health are verified; guard FINISHED.
The new `ctx1_rejoin_placement_v22` gate preserves the frozen protocol and
strict60s readiness, adds15 admission tests, and waits for manual placement
change and application-only reflash. Issue4 PASS remains false.

## Second retained rejoin

Run3411be0b68c840239dc78b46c2732d1e again proved rejoin/Announce/Timeout,
then readiness stopped on poll DSN103 NO_ACK. No FAN. Gen8/nextFC224 retained.
V17 and both-pair health are verified; guard FINISHED.
The next separately reviewed diagnostic image explicitly sets+8dBm;
strict readiness and no-retry policy remain unchanged. Hardware PASS is false.
