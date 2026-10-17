# AirNanny dual-PAN runtime V28

V28 is V27 with exactly one behavioural change, made after V27's Gate E
attempts 1, 3, 4 and 5 each lost a context to one rejoin-chain frame (REJOIN
twice, ANNOUNCE, END_DEVICE_TIMEOUT) that drew no ACK or a corrupted one:

- `tx_retry` (src/tx_lifecycle.inc) sends a **REJOIN, ANNOUNCE or TIMEOUT frame
  that went on air and drew no ACK or an invalid one** again, byte for byte --
  same DSN, same frame counter -- up to `MAC_MAX_FRAME_RETRIES` (3,
  include/management.h; 802.15.4's macMaxFrameRetries) more times before the
  context sees a failure. A parent that took the first copy and lost only its
  ACK drops the copy as a duplicate. Retries happen only within
  `TX_RETRY_WINDOW_US` (250 ms) of the host's intent, and the whole frame stays
  within `TX_INTENT_LIMIT_US` (2 s, V27's loosest watchdog), so the scheduler's
  3 s backstop still never fires.
- Polls keep V27's rule (a clean miss is retried by the next poll); TYPE07 and
  the beacon request stay single-shot; a frame that never went on air is the
  CCA backoff's business, as before.
- TXDONE/AUTO_DONE carry `mac_retries` as their last field; INFO reports
  `identity=airnanny_dual_pan_runtime_v28 version=28`. Nothing else in the wire
  changed (evidence/wire_surface.json).

Pinned by tests/test_mac_retry.c (20 checks, plain and sanitized), which drives
the real src/main.c through firmware_cli.c. Image:
releases/airnanny_dual_pan_runtime_v28.hex, built with the lineage toolchain.

Gates A-C were proven on V26, Gates C-D on V27. Gate E runs on V28 (operator's
decision, 2026-10-14), continuing from the stores V27's Gate E attempts left.

---

# AirNanny dual-PAN runtime V27

V27 is V26 with exactly one behavioural change, made after Gate C attempts 2-3
and Gate D attempt 1 each lost a context to a single keepalive poll that got no
ACK (or an ACK with a bad CRC) on a clear channel:

- `management_done` (src/rejoin_transport.c) no longer ends a context on a
  **clean miss of a MAC poll** -- no ACK, an invalid ACK, or a busy channel,
  with no abort and no ambiguity. The next poll asks again; a data request
  carries no frame counter and no security state. `MAX_CONSECUTIVE_POLL_MISSES`
  (3, include/management.h) misses in a row still end it.
- Every other failed TX -- REJOIN, ANNOUNCE, TIMEOUT, TYPE07, beacon request,
  and any aborted or ambiguous poll -- still ends the context on the first, as
  in V26.
- INFO reports `identity=airnanny_dual_pan_runtime_v27 version=27`; the wire
  protocol is otherwise byte-identical (evidence/wire_surface.json).

Pinned by tests/test_poll_misses.c, which also links the frozen V25 transport
and asserts the one intended divergence. Image: releases/airnanny_dual_pan_runtime_v27.hex,
built with the lineage toolchain (evidence/build_manifest.json).

Gates A-C were proven on V26 (../dual_pan_runtime_v26/evidence). On V27, Gate C
is repeated (operator's decision, 2026-10-13) and Gate D runs.

---

# V26: dual-PAN RAW runtime (in progress)

**OFFLINE SOFTWARE ONLY. No HEX, no flash, no COM, no RF. Issue #5 PASS false.**
V17 remains the frozen reference. Both context stores are untouched:
ctx0 `generation=19`/`next_fc=1280`, ctx1 `generation=16`/`next_fc=1088`.

Successor of [ctx1_rx_admission_v25](../ctx1_rx_admission_v25/) (transport
RADIOV9, single context). Plan and protocol contract:

- [DUAL_PAN_RUNTIME_PLAN.md](../DUAL_PAN_RUNTIME_PLAN.md)
- [DUAL_PAN_RADIO_PROTOCOL.md](../DUAL_PAN_RADIO_PROTOCOL.md) — RADIOV10 contract,
  with two amendments recording corrections to its own first draft
- [Phase 0 provenance](../evidence/dual_pan_phase0_provenance.json)

## What exists now

Phase 1.2, the two-context admission layer:

- `include/dual_context.h`, `src/dual_context.c` — paired two-entry
  configuration with atomic monotonic commit, classification, per-context
  bindings and the per-context ACK gate. Classification behaviour is carried
  over from the offline-tested `dual_pan_mac_gate` without relaxation.
- `src/dual_admit.c` — classify first, then run the V25 deep predicate against
  the binding of the selected context. No "try both keys" anywhere.
- `radio_driver/mac_features/nrf_802154_filter.c` — the only driver change:
  the existing `DUAL_PAN_GATE` hook now calls `dual_admit_part`. Two lines.
  `nrf_802154_core.c` needs no change, because V25 already contains every
  instrumentation call `dual_pan_mac_gate` added.

Phase 1.3, the one-radio TX scheduler:

- `include/dual_sched.h`, `src/dual_sched.c` — pure scheduling logic with no
  radio calls: one in-flight frame with a named owning context, immediate ACK
  and RX ahead of any transmission, bounded per-context queues, round robin
  across contexts with FIFO inside one, MAC tuple ownership checked at
  submission, completions routed only to the submitting context, deadline
  timeouts terminal and never retried, and a failure in one context leaving
  the other untouched.

Phase 1.4, the RADIOV10 transport records:

- `include/dual_records.h`, `src/dual_records.c` — command parsing and record
  formatting for the [protocol contract](../DUAL_PAN_RADIO_PROTOCOL.md).
  Parsing is where a wrong context would become a cross-context action, so
  `ctx` is mandatory and never defaulted, a repeated key is refused rather than
  resolved last-one-wins, an unknown key is refused rather than ignored, and
  `INFO`/`STATS`/`STATUS`/`END` refuse a `ctx` field outright. Formatting
  writes whole lines or nothing, and a frame outside both contexts is tagged
  `ctx=none`, never 0 or 1.

Phase 1.5a, pinned dual identity:

- `include/dual_identity.h`, `src/dual_identity.c` — the two networks this image
  may address, as compile-time constants. The first RADIOV10 draft let the host
  supply PAN, short and IEEE freely, which **broke an existing safety property**:
  every predecessor pinned its single context in file-scope constants on purpose,
  so an image could not address a network it was not built for. The dual analogue
  is a two-entry pinned table, not a host-filled one. The host still chooses
  whether a context is enabled, when it is bound and when it may ACK, and reports
  the current short, which a coordinator can reassign; it never chooses which
  network a context is. Enforced in `dual_config_valid` and `dual_binding_set`,
  so a frame carrying the other network's identity under our own PAN and short is
  refused on air.

Phase 1.5b, the context-parameterised transport:

- `src/rejoin_transport.c` — the state machines no longer pin one network.
  ctx1's RAW and trust-centre addresses were file-scope constants, and PAN
  `0x0b7a` was a literal in the beacon check, both poll builders, the typed and
  application envelopes and the response observation. All of it now reads the
  session's own `key_gate`, which `management_resume` fills from the pinned table
  for the context the `BIND` command names. `BIND` therefore requires `ctx`, and
  a missing one is refused rather than defaulted.
- Session budgets: 360 s and 400 polls become `SESSION_LIMIT_US` 3 900 s and
  `MAX_TOTAL_POLLS_PER_CONTEXT` 3 600, which a 60-minute dual soak needs at one
  poll per second per context. **Constraint found, not solved:** 3.9e9 µs leaves
  only about 6.6 minutes of margin to the 32-bit microsecond wrap at 4.295e9,
  and `main.c` stops the session when the clock goes backwards, so a wrap during
  a long soak terminates it. The soak has to be designed around that.

Phase 1.5c, the merged gate instrumentation:

- `include/gate_events.h`, `src/gate_events.c` — the union of both predecessors.
  V25's RX revision with its saturation and drop accounting, CRC snapshot and
  cutoff drain are kept because host freshness logic and the durable replay
  floors depend on them; mac_gate's context classification, configuration
  generation, per-context statistics and **hardware** ACK timing come across.
  The ring stays at 32, not mac_gate's 8, because dual traffic roughly doubles
  the RX rate. Every field name the inherited harnesses fill is unchanged, so
  `tests/firmware_cli.c` and `tests/scan_replay.c` compile without edits.
- Timing is captured by PPI into TIMER3: CRCOK, TXREADY, PHYEND and ADDRESS,
  because gate A measures the RX-to-ACK turnaround and no software read can.
- **An integration bug caught before it could exist.** V25's `gate_hw_now_us()`
  read `CC[0]` via a software capture; mac_gate's PPI captures CRCOK into that
  same `CC[0]`. Merged naively, any foreground clock read would have silently
  overwritten the hardware RX timestamp — corrupting precisely the measurement
  gate A depends on. Software reads moved to `CC[4]`, and a `_Static_assert` on
  the driver's PPI mask now fails the build rather than the measurement.

Phase 1.5d, two sessions in `main.c`:

- Two independent `commission_t`, with one `tx_t` because one radio means one
  frame in flight; the frame records its owner and the TX lifecycle reads it.
- `BIND` resumes the named context and then publishes its configuration entry
  and admission binding atomically, which is what opens that context's ACK.
- The PIB PAN and short address are no longer written: under `DUAL_PAN_GATE` the
  driver's destination filter is replaced, so they take no part in admission.
  V25 wrote them and stopped the radio to do it, which here would disturb the
  other context for nothing. For the same reason a discovery scan no longer
  retunes the radio to broadcast — it is a per-context state now, and the other
  context keeps receiving and answering throughout a scan.
- Automatic polls take turns, so two one-hertz pollers interleave; a context
  ready but not served is counted.
- A fault in the shared evidence path stops both contexts, because neither
  one's state can still be trusted. A fault belonging to one context stops only
  that context, which is the isolation the issue asks for.

Offline results: [evidence/dual_context_offline.json](evidence/dual_context_offline.json),
[evidence/dual_sessions_offline.json](evidence/dual_sessions_offline.json),
[evidence/gate_events_union_offline.json](evidence/gate_events_union_offline.json),
[evidence/dual_transport_offline.json](evidence/dual_transport_offline.json),
[evidence/dual_identity_offline.json](evidence/dual_identity_offline.json),
[evidence/dual_sched_offline.json](evidence/dual_sched_offline.json),
[evidence/dual_records_offline.json](evidence/dual_records_offline.json),
raw output in [tests.txt](tests.txt).

- `tests/test_dual_admit.c` — 120 checks, 0 failures, clean under
  `-Wall -Wextra -Werror -Wconversion` and under ASan + UBSan. 21 of those
  checks are the pinned-identity negatives: syntactically valid configurations
  and bindings naming the other network, or a foreign one, are refused.
- `tests/test_v25_equivalence.c` — the unmodified V25 `assoc_filter.c` is
  compiled into the same binary, bound to the same identity, and both
  predicates are driven over 40 960 synthetic frames. 11 admitted by both,
  40 949 refused by both, **zero** divergence either way. This is the evidence
  that no V25 check was removed or relaxed.
- `tests/test_dual_sched.c` — 137 checks, 0 failures, clean under the same
  flags and under ASan + UBSan.
- `tests/test_dual_records.c` — 98 checks, 0 failures, same flags and
  sanitizers.
- `tests/fuzz_dual_records.c` — 300 000 mutated commands under ASan + UBSan:
  2 950 accepted, 297 050 refused, **zero** contract-invariant violations and
  no crashes.

**The image links.** `tools/build.py` is ported: it locates the toolchain
rather than assuming one, so the same script runs with the operator's Windows
GCC and with a Linux GCC, and the manifest states whether the result is
bit-comparable with the lineage. It is incremental, because a full rebuild of
this tree over a mounted filesystem does not fit one bounded invocation, and its
input hashes are repository-relative so the evidence stays meaningful on another
machine.

First V26 image: text 59500, data 176, bss 51696, HEX
`C204CEFF…`, reproducible across runs, and correctly reported as **not**
bit-comparable with V17..V25. The growth over V25 is where the design says it
should be: `sessions` is 856 bytes for two `commission_t`, and the ring went
4608 → 5760, which is exactly 32 slots × 36 bytes of new record fields.
Verified with `arm-none-eabi-nm --size-sort`, not assumed.

**The release image exists and is bit-comparable with the lineage, but it is
already superseded and must not be flashed:** `src/main.c` gained `reason=` on
the RX record afterwards, so the image no longer matches the sources. The
guard's own `firmware_input_changed` check refuses it, which is the machinery
working rather than something to remember. One final Windows build is needed
once the firmware is final.

Nothing has been flashed. `releases/airnanny_dual_pan_runtime_v26.hex`,
SHA256 `1E2A2CB5…3ED727FE`, text 61568 / data 176 / bss 53204, built by the
operator's own ARM 7-2018-q2-update toolchain — the same distribution that built
V17..V25. The hash shown further down is the superseded 1.5e Linux build; see
[evidence/release_image_lineage.json](evidence/release_image_lineage.json).

Still not a passed gate: no RF has been emitted, no ACK timing measured on
hardware, and no guard exists yet. Gate A pins this hash and is written next. See [evidence/arm_image_offline.json](evidence/arm_image_offline.json).

- `tests/test_transport_equivalence.c` — 127 checks, 0 failures. The frozen V25
  `rejoin_transport.c` is compiled into the same binary with its names prefixed,
  and both implementations are driven over the same commands with ctx1 selected.
  Frames come out byte-identical and state matches, including a 512-variant
  beacon corpus and a 64-variant response corpus. ctx0 then resumes with its own
  pinned identity and emits its own PAN, which V25 could not do at all.

Total: **503 offline checks** plus the 40 960-frame filter corpus and the
300 000-iteration parser fuzz.

The inherited Python suites were also run in the device VM against the real
private stores, with the same suites run against V25 first to tell inherited
failures from new ones. Six are green before and after; `test_recovery` (1) and
`test_rx_deadline` (6) fail identically in V25 and are V18-era inheritance.
**No new failures.** That baseline earned its keep: it caught a tightening I had
introduced by accident, described below.

Pinning also exposed a latent defect in the test vectors themselves: the
extended-address constants had been written in the order of the hex string
rather than wire order. Both the synthetic frame and the binding used the same
wrong order, so comparisons matched and the logic was exercised correctly, which
is why it stayed hidden until the vectors met the firmware's own wire-order
constants. Corrected in all three affected suites; the equivalence corpus was
re-run afterwards and still shows zero divergence.

```
gcc -std=c11 -Wall -Wextra -Werror -O1 -Iinclude -Iradio_driver -Itests \
    -o test_dual_admit tests/test_dual_admit.c src/dual_context.c src/dual_admit.c

gcc -std=c11 -Wall -Wextra -O1 -Iinclude -Iradio_driver -Itests \
    -o test_equiv tests/test_v25_equivalence.c src/dual_context.c src/dual_admit.c \
    ../ctx1_rx_admission_v25/src/assoc_filter.c
```

## Requirement found while building this

V25 gated immediate ACK with one session-wide condition
(`phase != G_MANAGEMENT || recovery.phase == R_SCANNING`). In a dual runtime
that would silence **both** contexts whenever either one scanned. The gate is
therefore per context here, and a test asserts that ctx0 stays admitted while
ctx1 scans. This requirement appears neither in issue #5 nor in any earlier
document in this directory.

## What does not exist yet

The contract's generic `TX` verb is not implemented, and nothing needs it until
issue #6.

No hardware gate has been prepared or reviewed, and no guard exists. The ARM
image links and is measured (phase 1.5e) but **is not a release candidate** —
see [evidence/arm_image_offline.json](evidence/arm_image_offline.json).

One constraint is recorded rather than solved: the hardware microsecond clock is
32 bits and wraps at about 71.6 minutes, and `main.c` stops on a backwards
clock. A 60-minute soak has to be designed around that, not into it.

Only the operator flashes the dongle, manually, through the established
application-only workflow.

## The transport envelope: RADIOV10 with a mandatory `ctx`

The command set now speaks `RADIOV10`, and the wire version exists in exactly
one place — [include/radio_wire.h](include/radio_wire.h). The lineage spelled
`RADIOV9` into roughly thirty string literals across firmware, host and tests,
which is how a firmware comes to emit two versions on one link: the parser
accepts the new spelling while some rarely taken record still prints the old
one, and the host's prefix check passes until exactly that record appears.

`ctx` is mandatory on all ten per-context verbs, optional on `STATUS`, and
**refused** on `INFO` and `END`. An action may never default to a context: with
two networks a guessed `ctx` is a frame sent into the wrong one with the wrong
key. A report may default, so `STATUS` describes the single bound context and
always names which one it described. The two global verbs refuse a scope they do
not have, because ignoring a `ctx` reads to the host as accepting it.

Two corrections to my own first draft of the contract are recorded as explicit
amendments in [DUAL_PAN_RADIO_PROTOCOL.md](../DUAL_PAN_RADIO_PROTOCOL.md):

- The draft described one generic `TX` and assumed the nine typed commissioning
  verbs would become its special cases. They cannot, without losing checks. The
  typed path validates frame-counter monotonicity (`fc >= last_fc + 32`), the
  aux header's `0x28`, its `fc`, its `raw_ieee` and its `keyseq`, the inner
  `tc_ieee`/`raw_ieee`, the exact length per class, the one-shot phase gates and
  a `permit_hash` match — which is exactly the separation issue #5 asks to be
  proven (`frame ctx == key ctx == RAW IEEE ctx == FC allocator ctx`).
  Collapsing them would move those checks off the firmware in exchange for a
  shorter document. The typed verbs therefore carry into RADIOV10 with their
  predicates intact; the cost, a wider contract and a host that must know frame
  classes, is stated rather than hidden.
- The draft wrote `version=10` in `INFO`, collapsing the firmware revision and
  the wire version into one field. `INFO` now emits `version=26 wire=10`, and
  the host keeps one copy of the wire version and verifies it against `wire=`
  rather than trusting it.

## The scheduler on the real transmit path

`dual_sched` now owns the decision of what goes on air next. `tx_t` still owns
the transmission itself — its CCA backoff, its abort paths, its watchdog and its
completion guarantees. The two are not alternatives: the scheduler arbitrates
between contexts, the lifecycle runs the one frame that won, and `tx_finish` is
the single terminal point and the only place the scheduler is told a frame is
over.

V25 refused any host command while a frame was in flight. With one radio and two
contexts that would drop either context's steady one hertz poll whenever the
other held the radio — the starvation issue #5 asks to be bounded. A TX verb is
now queued instead of refused. Control verbs (`BIND` and the three commit verbs)
still require a free radio, because they republish configuration and bindings
and touch the ACK gate, and doing that underneath the other context's
transmission buys nothing and risks the one obligation this firmware cannot miss.

Two things are stated rather than implied. The queue is configured at depth 4
but **this runtime cannot reach depth 2**: `management_tx` commits a context's
session state to a frame by the time it returns and refuses while
`recovery.pending` is set, so the protocol bounds a context to one outstanding
frame upstream of any scheduler. No deep queue has been proven here; the depth
will matter for issue #6. And `rx_busy`/`ack_busy` are passed `false` on purpose:
the Nordic driver owns RX and auto-ACK precedence over a transmit request, and
main.c has no truthful instantaneous "an ACK is on air right now" signal.
Feeding a guessed one would be worse than feeding none, because the module's two
deferral counters would then read as measurements. They stay at zero in firmware.

### The defect wiring it up found

The scheduler refused the active discovery beacon request with `sched_length`, so
no context could ever have scanned. Its ownership check assumed every frame
carries the context's PAN at offset 3 and its short as MAC source at offset 7,
and imposed a nine-byte floor to read them. A beacon request is FCF `0x0803` — a
MAC command with no source address and a broadcast destination, eight bytes long.
It is the one frame a context sends *before* it can name itself, so it carries no
tuple at all.

The check is now class-aware on the frame's own evidence rather than the caller's
claim, and for the sourceless broadcast case the requirement is **stronger** than
a tuple check: the frame must be byte-for-byte the reviewed template, variable
only in its sequence number. Completion still routes by host id and never by
anything read out of the frame.

Worth naming why this survived 137 passing checks: `dual_sched` was written and
tested in isolation against synthetic frames that all had the outgoing shape.
Nothing exercised it against the frame set the firmware actually builds. Those
checks were not wrong, they were incomplete in a way only integration could
reveal — and `test_mac_backoff` went from OK to four failures the moment the
scheduler reached the real path, which is what the inherited baseline is for.

## `STATS`: the counters become observable

The admission and scheduler counters existed since phases 1.2 and 1.3, but
nothing could read them off a running device — so nothing issue #5 asks to be
*measured* (classification outcomes, ACK suppression, per-context TX accounting,
fairness) was actually measurable. `RADIOV10 STATS id=<n> boot=<id>` is a global
read-only report; `ctx` is refused on it, as on `INFO` and `END`.

It is answered **before** the `capture_loss` check, unlike every other verb.
Acting on lost evidence is unsafe, but a read-only report is the opposite case:
when evidence has been lost the counters are the most useful thing left to read,
and refusing to show them is the opposite of what a diagnostic is for.

Beyond the two stats structs the record carries two of the firmware's own
numbers: `starved_polls`, a context that was due to poll and could not be offered
— the fairness number the issue asks to be bounded — and `routing_faults`, which
**must stay zero** because it means the TX lifecycle and the scheduler disagree
about which frame owns the radio.

Writing it found two defects in my own earlier code. `dual_format_stats` emitted
no `id=`, so the host could never have awaited its own request — the bounded wait
would just time out, and the formatter's 98 passing checks had not noticed
because nothing awaited it. And `sched_backstop_fired` from 1.7 was dead state:
set when the scheduler's deadline backstop fired, never read. The condition is a
real fault, and recording it in a flag nobody reads makes it invisible except as
a stop with no stated cause. Both it and a refused completion now count into
`routing_faults`: one failure class, one observable counter.

## The release image is built by the lineage toolchain

Asked whether to flash an image built by a different compiler build than the
five that have hardware proof, the operator chose to run the build with their
own toolchain — and that is the right call: it is a question about accepted risk
on hardware in daily use, not one the offline evidence settles.

I could not run it myself, and tried every route: the linked shell is a Linux VM
that cannot execute the lineage `.exe`, wine is not installable without root,
ARM's own Linux build of the identical toolchain is 403 from the egress proxy,
and computer use — which would have launched it by a double-click with no typing
— was declined. So the handover is `build_v26_windows.ps1`: one command, running
`tools/build.py` unchanged, flashing nothing.

Two defects were caught in that handover before it ran. `build/` held 66 objects
compiled by the Linux VM, all newer than their sources, and `build.py` reuses any
object newer than its source — so a Windows build would have linked Linux objects
and reported success on an image belonging to neither toolchain. And the first
version of the guard against that was itself broken:
`Get-ChildItem -Path 'build' -Include *.o` silently matches nothing in
PowerShell, because `-Include` applies only when the path ends in a wildcard.
The block that existed to prevent the trap would have done nothing. Corrected to
`build\*` with an explicit post-check; the run then reported clearing 70 files.

The result is verified rather than taken on trust: all 83 repository-relative
input hashes in the Windows manifest were re-checked against this tree's own
sources, zero mismatches, so the image was built from exactly the reviewed code.

One unplanned result fell out of it. The Linux-versus-lineage delta measured on
V25 was +568 text / +12 bss, a single measurement that could have been a
coincidence of that build. V26 reproduces it at **+572 / +12** on different
sources — so it is a stable toolchain property, and the scheduler's bss cost
under the lineage toolchain is 1508 rather than 1520.

## The native corpus is reproducible now

Through phases 1.1 to 1.5 the native suites existed only as commands typed by
hand, and the detail that mattered most — how the frozen V25 transport is linked
beside the new one — lived in a sentence in this README instead of in a build
line. A corpus nobody else can rebuild is not evidence, so it is now
[tests/run_native.sh](tests/run_native.sh), which produces identical output in
the cloud container and in the device VM.

Writing it down found three defects in my own build line, none of which were in
the code under test: it reached into the SDK's nrfx headers for driver types
when `tests/` already holds host shims (an SDK-based host build drags in
Cortex-M register definitions and is either broken or quietly wrong about word
size); it compiled the frozen V25 object with V26's include path as well as its
own, so the rename macros rewrote V26's declarations and the prefixed name was
declared with one signature and defined with another; and it applied `-Werror`
to frozen V25 source, whose dense style trips `-Wmisleading-indentation` — the
right response to a warning in frozen evidence is to not edit it.

The Python baseline is also complete for the first time. Earlier phases measured
eight of the twelve suites, which means a failure in the other four could not
have been attributed to anything. All twelve are now measured in both trees:
seven pass, and five fail **identically in V25**, so they are inheritance rather
than regression. No new failures.


## A tightening I introduced by accident

The pinned identity table first carried `min_generation` set to each store's
current generation (19 and 16), and `management_resume` refused anything below
it. That was wrong twice over. It silently tightened behaviour beyond
parameterisation, which broke the inherited suites that bind at generation 6 and
13. And a store's generation advances every session — ctx1 went 13, 14, 15, 16 —
so pinning it into the image would demand a rebuild after every run.

`min_generation` is gone. `DUAL_GENERATION_FLOOR` keeps V25's exact floor of 6,
and real rollback protection stays where it already lives: the host's durable
store, which holds the live generation and the outgoing counter high-water.

The regression baseline is what caught it, within one run of taking it.

## What the inherited suites caught in the dual rewrite

These suites compile the actual `main.c` through `tests/firmware_cli.c`, so they
exercise the dual runtime rather than a model of it. They found five real
defects, four of them mine and one latent in the design I had written earlier:

1. **`MATCH_CTX0` was the zero value of `dual_match_t`.** A zeroed or partially
   initialised record therefore claimed membership of ctx0. `MATCH_NONE` is now
   zero, so an uninitialised record means *belongs to nobody*.
2. A macro redirected the TX lifecycle to the owning session — but `session` is
   also a struct field name, so it rewrote `tx.session` too. Made explicit.
3. **Beacons were routed through the classifier.** That classifier is scoped to
   addressed DATA on purpose, because that is what an immediate ACK may answer;
   a beacon is frame type 0 with no destination, so it classifies as
   *unsupported*, not *broadcast* as I had assumed, and discovery would never
   have seen one. Unattributed frames now go to both contexts, each validating
   PAN and both identities against its own keys — which is also exactly what the
   single-context predecessor did with every frame.
4. "Bound" was tested as `phase != G_IDLE`, but stopping the runtime leaves a
   never-resumed context in `G_STOPPED`, which then looked bound and answered a
   STATUS with a session number it never had.
5. A STATUS naming no context, taken after a *rejected* bind, described the
   wrong context and hid the stop. It now describes the one bound context when
   exactly one is, otherwise the context a command last acted on, and always
   names which. An action still never defaults.
