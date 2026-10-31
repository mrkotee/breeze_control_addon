# V34: the amplified dongle

Candidate based on V33. **Not flashed, no hardware run, no RF performed.** V34
exists only to move the proven V33 runtime onto a different radio board: the
Holyiot 21017 nRF52840+PA USB dongle, which puts an RFX2401C front-end module
and an external antenna where the PCA10059 had a PCB antenna and nothing else.

Application-only image: `releases/airnanny_dual_pan_runtime_v34.hex`, starting
at 0x1000. All HEX data is within 0x1000..0x10E83; no MBR or bootloader data is
present. Preserve MBR/bootloader and both durable security stores.
SHA256: `c6e159bb0f1a3c976c8ab046a716fe7389b588cddea6582c1a23d10912b2bb57`.

Flashing and the measurement that confirms the amplifier is really being driven:
[PA_DONGLE_MIGRATION.md](../PA_DONGLE_MIGRATION.md).

## Why a new image was necessary and not merely desirable

The RFX2401C has no bypass path. With TXEN and RXEN both low it is asleep and
passes nothing in either direction. V33 never drives those pins, because on the
PCA10059 there was nothing to drive — so **V33 flashed to the new dongle would
enumerate on USB, answer INFO and STATUS, and be deaf and mute on the air.** The
swap is not a question of getting more range out of the same firmware; without
this change the new dongle does not work at all.

## What changed

Exactly three files differ from V33, and `tools/test_runtime.py` asserts that
set and fails the build if anything else moves:

| File | Change |
| --- | --- |
| `include/board_fem.h` | New. The board: amplifier pins, drive level, PPI/GPIOTE allocation, and the provenance of each number. |
| `include/gate_radio_config.h` | `ENABLE_FEM` 0 → 1. |
| `src/main.c` | `fem_configure()` arms the amplifier between `nrf_802154_init()` and the first receive; `radio_power_configure()` asks for the board's drive level instead of a hard-coded +8; identity v33 → v34. |

`radio_driver/` is **byte-identical to V33**, and therefore to V32, which is
where the hardware proof for the ACK, CCA, admission and RX-fence paths lives.
The amplifier is reached through the driver's existing FEM hooks, which were
compiled out before and are compiled in now — the build adds one Nordic
translation unit, `fem/three_pin_gpio/nrf_fem_three_pin_gpio.c`, and swaps the
FEM include directory from `fem/none` to `fem/three_pin_gpio`. No protocol,
wire, scheduler, recovery or security behaviour is touched.

`nrf_802154_init()` does not configure the amplifier; the only thing that arms
it is the explicit `nrf_fem_interface_configuration_set()` call in `main.c`.
Setting `ENABLE_FEM=1` alone compiles, links and boots, and still transmits
nothing. If the call fails or reads back wrong the boot fails, deliberately: a
dongle that came up with an unconfigured amplifier would look healthy on USB and
be invisible on the air, which is the worst of the available outcomes.

## Power, and why it went down

| | V33 (PCA10059) | V34 (Holyiot 21017) |
| --- | --- | --- |
| SoC TXPOWER | +8 dBm | **-4 dBm** |
| At the antenna port | +8 dBm (6 mW) | ~+18 dBm (63 mW) |
| Antenna | PCB | external, ~2 dBi |
| Receive | bare SoC | LNA, ~11 dB |

The SoC figure dropping is not a reduction. The RFX2401C adds about 22 dB and
saturates near +22 dBm; feeding it V33's +8 dBm would ask for +30 dBm, which it
cannot produce. What comes out instead is a compressed O-QPSK signal — worse
EVM, spectral regrowth into the neighbouring channels, and a *higher* packet
error rate than a clean quieter one. -4 dBm keeps the amplifier linear and still
puts about +10 dB more on the air than V33 before counting the antenna, and the
LNA improves the receive side by roughly as much again.

~+18 dBm into a 2 dBi antenna is about 100 mW EIRP, which is the civil 2.4 GHz
ceiling in the EU and in Russia. 0 dBm at the SoC (~+22 dBm out, at the
compression knee) is the next step up and would exceed it. The value is one line
in `include/board_fem.h`; change it, rebuild, and the new figure appears in INFO
`tx_power_dbm`.

Note that `tx_power_dbm` now reports the **SoC's** drive level, not what leaves
the antenna. The host reads the field and asserts nothing about it.

## Pin provenance — the one thing not verified

Holyiot publishes no schematic for the 21017. `BOARD_FEM_PA_PIN` (P0.24, TXEN)
and `BOARD_FEM_LNA_PIN` (P0.22, RXEN) come from two independent third-party
sources that agree: a Zephyr port of this exact module, and a Nordic DevZone
thread whose author states they read the pins off the Holyiot schematic. Neither
is a vendor document, and no hardware here has confirmed them.

If they are wrong the failure is obvious and harmless — the link is no better
than before, or dead, and RX RSSI does not improve. Nothing in this image can
damage the board. The migration document has the measurement that settles it and
the two alternative mappings to try.

## Offline results

| Check | Result |
| --- | --- |
| Native C suite (`tools/test_runtime.py`) | 2175 checks, 0 failures, firmware delta asserted exactly |
| Native FEM/power readback (`tools/build_power_test.py`) | `FEM_PA24_LNA22_TXPOWER-4_CONFIG_READBACK_PASS` |
| Host unit tests | 1852 passed |
| Image/manifest/source binding (`run_radio_service.preflight(34)`) | PASS |
| ARM build | lineage toolchain 7-2018-q2-update, bit-comparable with the V17..V25 lineage |

Sizes: text 64940, data 216, bss 53236 (V33: 62468 / 176 / 53236). The ~2.4 KB
of text is the Nordic FEM translation unit.

Two stale tools were repaired in passing, both of which had stopped working
before V34 and neither of which affects the image: `tools/build_power_test.py`
carried the pre-dual-PAN source list and no longer linked, and the firmware-delta
check in `tools/test_runtime.py` walked only the predecessor's files, so a newly
added header was invisible to the check whose job is to notice new things.

`tools/review.py` is still the inherited V22 script and still does not run here;
it was already dead in V33 and V34 did not revive it.

## Hardware scope

None. No image has been flashed, no COM port opened and no RF performed for
V34. V33 remains the running firmware and the only one with hardware proof on
this project's networks; V34 inherits none of it. The host deliberately keeps
its `firmware_version==33` gates on the V33 hardware-evidence records, so V34
cannot present V33's proof as its own.
