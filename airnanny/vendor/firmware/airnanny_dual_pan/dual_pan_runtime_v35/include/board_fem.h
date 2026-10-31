/* Front-end module (PA/LNA) description for the Holyiot 21017 nRF52840+PA USB
 * dongle, and the one place where the board's RF numbers live.
 *
 * V33 and everything before it ran on the Nordic PCA10059 dongle: a bare
 * nRF52840 with a PCB antenna, driven at the SoC maximum of +8 dBm. The
 * replacement dongle puts an RFX2401C front-end between the SoC and an external
 * antenna, so the radio is no longer wired straight to the air and the driver
 * has to key the amplifier in step with every ramp-up.
 *
 * The RFX2401C has no bypass path. With TXEN and RXEN both low it is asleep and
 * passes nothing in either direction, so a firmware that does not drive these
 * pins is deaf and mute on this board -- V33 does not drive them. That is why
 * this file and ENABLE_FEM exist, and why V33's image must not be flashed to
 * the new dongle and expected to work.
 *
 * PIN PROVENANCE, READ THIS BEFORE TRUSTING IT. Holyiot publishes no schematic
 * for the 21017. The two assignments below come from two independent
 * third-party sources that agree -- a Zephyr port of this exact module and a
 * Nordic DevZone thread whose author says they read them off the Holyiot
 * schematic. Neither is a vendor document. If the pins are wrong the symptom is
 * unambiguous and harmless: the link is no better than before, or dead, and RX
 * RSSI does not improve. Nothing here can damage the board. VERIFY_PA.md has
 * the measurement that settles it and the two alternative mappings to try.
 */
#ifndef BOARD_FEM_H
#define BOARD_FEM_H

/* RFX2401C control pins, active high, no PDN/CSD line brought out. */
#define BOARD_FEM_PA_PIN         24  /* P0.24 <- FEM TXEN */
#define BOARD_FEM_LNA_PIN        22  /* P0.22 <- FEM RXEN */
#define BOARD_FEM_PA_ACTIVE_HIGH  1
#define BOARD_FEM_LNA_ACTIVE_HIGH 1
#define BOARD_FEM_PDN_ENABLED     0

/* Datasheet small-signal figures, recorded so the link budget in the README is
 * checkable. The driver in this SDK does not act on them; they feed only
 * nrf_802154_fal_pa_is_configured(), which nothing in this image calls. */
#define BOARD_FEM_PA_GAIN_DB     22
#define BOARD_FEM_LNA_GAIN_DB    11

/* SoC TXPOWER with the amplifier in circuit.
 *
 * The RFX2401C saturates at about +22 dBm, so its gain only holds while the
 * input stays well below that. V33's +8 dBm would ask it for +30 dBm: it cannot
 * deliver that, and what comes out instead is a compressed O-QPSK constellation
 * -- worse EVM, spectral regrowth into the neighbouring channels, and a higher
 * packet error rate than a clean, quieter signal. Driving a PA hard is not the
 * same as transmitting further.
 *
 * -4 dBm in gives roughly +18 dBm (63 mW) out with the amplifier still linear.
 * With the supplied 2 dBi antenna that is about 100 mW EIRP, which is the civil
 * 2.4 GHz ceiling in the EU and Russia, and it is still +10 dB on V33 before
 * counting the antenna or the LNA's help on receive.
 *
 * The next step up is 0 (about +22 dBm, at the compression knee); the step down
 * is -8. Both are legal values for the SoC. Change this one line, rebuild, and
 * the new figure is reported in INFO tx_power_dbm -- see README.md. */
#define BOARD_SOC_TX_POWER_DBM   (-4)

/* Clear-channel threshold, moved by the amplifier's receive gain.
 *
 * The driver's default is 0x14, and nrf_802154_ccaedthres_from_dbm_calculate()
 * is `dbm - ED_MIN_DBM` with ED_MIN_DBM -94, so 0x14 is exactly -74 dBm. That
 * number was chosen when the radio was wired straight to a PCB antenna. The LNA
 * now sits in front of it and lifts everything the energy detector measures by
 * its gain, so an unchanged threshold calls the channel busy where it used to
 * call it clear -- the receiver got better at hearing distant networks and
 * would defer to them. The symptom is deferred transmissions, backoffs and
 * cca_fail, not a wrong measurement anyone would see.
 *
 * Shifting the threshold by the same gain keeps the real-world figure at
 * -74 dBm: -74 + 11 = -63 dBm, which the helper turns into 0x1F.
 *
 * The LNA's gain and not the measured end-to-end improvement, although the
 * dongle gained about 18 dB in all. Energy detection should report the power at
 * the antenna connector, and the LNA is precisely the element that makes the
 * radio's reading differ from it. A better antenna genuinely puts more signal
 * on that connector, which is not an error to compensate for.
 *
 * V34 did not set this at all -- nothing in the firmware called
 * nrf_802154_cca_cfg_set, so the default stood. */
#define BOARD_CCA_ED_THRESHOLD_DBM (-74 + BOARD_FEM_LNA_GAIN_DB)

/* PPI and GPIOTE resources for the amplifier. The 802.15.4 driver owns PPI
 * 6..14 (nrf_802154_peripherals.h); the SDK's FEM defaults of 15, 16 and 5 sit
 * outside that, and nothing else in this image uses GPIOTE. These are the SDK
 * defaults, restated here so a future reader can see the allocation is
 * deliberate rather than inherited. */
#define BOARD_FEM_PPI_SET        15
#define BOARD_FEM_PPI_CLR        16
#define BOARD_FEM_PPI_PDN         5
#define BOARD_FEM_GPIOTE_PA       7
#define BOARD_FEM_GPIOTE_LNA      6
#define BOARD_FEM_GPIOTE_PDN      5

/* Time the pin is asserted before the radio ramp. The RFX2401C settles in about
 * a microsecond; the SDK default of 13 us is used unchanged because it also
 * sets the instant the driver transmits an immediate ACK, and this image's
 * whole value is that the ACK lands inside the 802.15.4 turnaround. Keeping the
 * stock number keeps that path on the timing Nordic ships and tests. */
#define BOARD_FEM_PA_GAP_US      13
#define BOARD_FEM_LNA_GAP_US     13

#endif /* BOARD_FEM_H */
