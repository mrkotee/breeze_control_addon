# Operator handoff — fresh attempt after wrong A7

Current checkpoint: first attempt closed with zero RF TX; V17 recovered and both pairs healthy. The target is the other A7 on PAN0B7A, not the second-bedroom A7 from issue #3. The new guard is hardware_gate_v2; hardware_gate_v1 is permanently consumed. Do not run `execute` as part of
offline review. All programming is manual through the operator's established
nRF Connect Programmer workflow; scripts never flash or restore an image.

## Historical software preparation (do not rerun after hardware)

Use the bundled modern Python (the system Python 3.7 cannot run these modules):

```powershell
Set-Location 'C:\Users\User\Desktop\airnanny\breeze_control\firmware\airnanny_dual_pan\second_a7_provisioning_v1'
$taskPython = 'C:\Users\User\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $taskPython prepare.py
& $taskPython tools/native_build.py
& $taskPython tools/build.py
& $taskPython candidates.py
& $taskPython verify.py
& $taskPython retry_after_wrong_pan.py preflight
```

These operations read local files, compile firmware and run synthetic fixtures.
They neither enumerate USB nor open COM. `prepare.py` preserves the persistent
RAW IEEE and fails on an identity conflict. `candidates.py` stores independently
verified historical candidates in ctx1 DPAPI storage, with no live authority.
`verify.py` freezes exact source bindings and compares protected predecessors.
Do not rerun/regenerate the evidence after starting a hardware guard; it is bound
immutably to that report. Hardware observations belong in the consumed run.

## When the operator resumes hardware work

1. Confirm both original pairs work, data updates, no CHECK CASE, no re-pairing,
   automation paused, and original settings. Save actual confirmations in an
   ignored `.local/physical_before.json` with boolean fields `both_healthy`,
   `automation_paused`, `no_check_case`, `current_data`, `settings_confirmed`,
   `manual_flash_only`, `pairing_A7_only` all true, plus `target_A7_PAN: "0B7A"`.
2. Run `retry_after_wrong_pan.py start --physical .local/physical_before.json`. It creates a
   permanent one-shot milestone and outputs its run UUID without opening COM.
3. The operator manually installs only the ctx1 commissioning application HEX
   from `releases/airnanny_ctx1_commission_v7.hex`. Verify its reported SHA256
   against the result document. Preserve MBR, bootloader and data; no erase-all.
4. After the operator reports completion, record it with
   `retry_after_wrong_pan.py record-flash --run <UUID>`. Then explicitly invoke
   `retry_after_wrong_pan.py execute --run <UUID>` for a single serial session. Device selection
   requires VID1915/PID1337/serialC625E0B966C1; COM number alone is insufficient.
5. Only after actual `PERMIT_ARMED`, enable pairing on the selected **A7 only**,
   holding power about 15 seconds until it blinks, then releasing. Leave the
   physical AirControl paired. No prompts, USB reopening or flashing occur
   between association response, current-short commit, key polling and announce.
6. The gate ends at MANAGEMENT_PENDING or a failure and requests manual V17
   recovery. Never rerun a consumed guard, reclaim a leased FC block or retry
   an ambiguous Device Announce. Preserve the complete run and ciphertext RX.
7. The operator manually restores
   `../../airnanny_v17/releases/airnanny_status_v17_machine_serial.hex`. SHA256:
   `2FFFE202FC0B8766113CADF92156B76A98942B64A0E4F3D3692513F210575193`.
   Record `retry_after_wrong_pan.py record-restore --run <UUID>`, then
   `retry_after_wrong_pan.py inspect-recovery --run <UUID>` issues exactly one local V17 INFO.
   Confirm both rooms and both original controllers, current data, no CHECK CASE,
   no re-pairing; save actual booleans in `.local/physical_after.json` and run
   `retry_after_wrong_pan.py finish --run <UUID> --physical .local/physical_after.json`.

## Continuation depends on actual ctx1 commissioning evidence

The real independent short, epoch UUID, attempt UUID, key sequence, outgoing FC
high-water and authenticated post-announce management RX do not exist yet.
They must come from the consumed ctx1 run, not from ctx0 or synthetic fixtures.
After reading those results, bind the existing reviewed management/readiness
pipeline to ctx1. An authenticated Leave60 requires the reviewed recovery path;
unknown semantics or a different key sequence stop for narrow compatibility
review. Do not reset/unpair the original controller to force a result.

Only after fresh live readiness may one low-risk adjacent FAN TYPE07 be built
from a fresh authenticated lossless original-controller baseline and current A7
TYPE06. Reserve the current independent ctx1 NWK FC durably, submit once, never
retry and require a fresh correlated authenticated TYPE06 confirmation. Finally
restore V17 manually, verify both rooms, compare ctx0 authority again and append
actual acceptance evidence. Historical or synthetic readiness cannot satisfy this.

This preparation intentionally creates no automatic hardware continuation.

