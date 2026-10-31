# V35: the clear-channel threshold follows the amplifier

Candidate based on V34. **Not flashed, no hardware run, no RF performed.** V35
sets one thing V34 left at its default: the CCA energy-detect threshold, which
was chosen for a radio with no amplifier in front of it.

Application-only image: `releases/airnanny_dual_pan_runtime_v35.hex`, starting
at 0x1000. All HEX data is within 0x1000..0x10FDB; no MBR or bootloader data is
present. Preserve MBR/bootloader and both durable security stores.
SHA256: `7c1b7fe930ca67276bb32080a6bfdbd915da73172b478aaf34f689fa8938891c`.

Same dongle and procedure as V34:
[PA_DONGLE_MIGRATION.md](../PA_DONGLE_MIGRATION.md).

## What was wrong

The driver's default is `NRF_802154_CCA_ED_THRESHOLD_DEFAULT 0x14`, and
`nrf_802154_ccaedthres_from_dbm_calculate()` is `dbm - ED_MIN_DBM` with
`ED_MIN_DBM` of -94 — so 0x14 is exactly **-74 dBm**. Nothing in V34 called
`nrf_802154_cca_cfg_set`, so that default stood.

The LNA sits in front of the energy detector and lifts everything it measures by
its gain. With the threshold unchanged, the radio calls the channel busy where
it used to call it clear: the receiver became better at hearing distant networks
and then deferred to them. The symptom is not a wrong reading anyone would see —
it is deferred transmissions, CCA backoffs and `cca_fail`.

V35 shifts the threshold by the same gain, so the real-world figure stays at
-74 dBm: `-74 + 11 = -63 dBm`, which the helper turns into **0x1F**.

**The LNA's gain and nothing else**, although the dongle gained about 18 dB end
to end. Energy detection should report the power at the antenna connector, and
the LNA is precisely the element that makes the radio's reading differ from it.
A better antenna genuinely puts more signal on that connector, which is not an
error to compensate for.

CCA is live on this image despite `NRF_802154_CSMA_CA_ENABLED 0`: that setting
disables the *driver's* CSMA-CA, while the firmware runs its own
(`src/cca_backoff.inc`, and `cca_preair`/`cca_attempts`/`cca_busy`/`cca_be` in
STATUS) on top of the driver's CCA. The threshold is used.

## What changed

Two files differ from V34, and `tools/test_runtime.py` asserts that set:

| File | Change |
| --- | --- |
| `include/board_fem.h` | `BOARD_CCA_ED_THRESHOLD_DBM`, defined as `-74 + BOARD_FEM_LNA_GAIN_DB`, with the arithmetic and the reason for the number. |
| `src/main.c` | `cca_configure()` with a readback, called beside `fem_configure()`; identity v34 → v35. |

`radio_driver/` stays **byte-identical to V34**, and so to V33 and V32. No
protocol, wire, scheduler, recovery or security behaviour is touched, and the
host profile for 35 is V33's unchanged.

Only `mode` and `ed_threshold` are set. `nrf_802154_pib_cca_cfg_set()` handles
each mode separately and in ED mode copies exactly those two, leaving the
correlator fields at their defaults rather than taking zeros from the caller.
The temperature correction is applied by the driver itself
(`nrf_802154_core.c:426`, via `nrf_802154_rssi_cca_ed_threshold_corrected_get`),
so the firmware sets the nominal value and nothing here duplicates that.

`nrf_802154_cca_cfg_set()` returns nothing, so the readback is the only evidence
in the image that the PIB holds what this build intends — the same reason
`fem_configure()` reads back. A disagreement fails the boot.

## Offline results

| Check | Result |
| --- | --- |
| Native C suite (`tools/test_runtime.py`) | 2175 checks, 0 failures, firmware delta asserted exactly |
| Native FEM/CCA/power readback | `FEM_PA24_LNA22_TXPOWER-4_CCA-63dBm_0x1F_CONFIG_READBACK_PASS` |
| Host unit tests | 1939 passed |
| `run_radio_service.py --preflight --firmware-version 35` | PASS, `late_join: true` |
| ARM build | lineage toolchain 7-2018-q2-update, bit-comparable with the V17..V25 lineage |

Sizes: text 65284, data 216, bss 53236 (V34: 64940 / 216 / 53236).

The native test asserts the register value the firmware writes, computed from
dBm the same way the driver does, and that the threshold went *up*: a wrong sign
or a dropped gain shows up as a number offline rather than as deferred
transmissions on the hardware.

## Hardware scope

None. No image has been flashed, no COM port opened and no RF performed for
V35. V34's own hardware scope is limited to what
[PA_DONGLE_MIGRATION.md](../PA_DONGLE_MIGRATION.md) records: the amplifier's
receive path measured at +18.6 dB and its transmit path confirmed by
acknowledged frames from the unit. V35 inherits neither that nor V33's proof.

This change does not address the `UNEXPECTED_SERIAL_PROTOCOL` latch seen on
V34 — that is a serial-line fault, not an RF one. A CCA threshold 11 dB too
sensitive could plausibly have contributed to recovery cycles not completing,
but nothing observed so far establishes that it did.
