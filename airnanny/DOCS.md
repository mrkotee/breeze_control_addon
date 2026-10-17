# AirNanny Dual-PAN Bridge

Bridges two AirNanny A7 units to Home Assistant over MQTT. Each unit lives on
its own Zigbee PAN and is reached through a single nRF52840 dongle running the
dual-PAN firmware.

The add-on publishes state only from confirmed device state. A command sent
from Home Assistant is never reflected as state until the device confirms it.

## Before you install

You need all of the following:

- an nRF52840 dongle already flashed with the dual-PAN runtime and plugged into
  the machine running Home Assistant;
- both A7 units already provisioned, with their durable security stores copied
  onto this machine (see **Durable stores** below);
- the Mosquitto broker add-on installed and started;
- the network key and verification digest for each context.

This add-on does not commission devices, generate identities, or re-pair
anything. It refuses to start rather than recreate state it cannot find.

## Configuration

| Option | Meaning |
| --- | --- |
| `firmware_version` | Dual-PAN runtime version on the dongle. Only `33` is accepted. |
| `ctx0_network_key` | Network key for context 0 — second bedroom, PAN `FA9B`. 32 hex characters. |
| `ctx1_network_key` | Network key for context 1 — bedroom, PAN `0B7A`. 32 hex characters. |
| `ctx0_key_sha256` | Verification digest for the context 0 key. |
| `ctx1_key_sha256` | Verification digest for the context 1 key. |
| `log_level` | `debug`, `info`, `warning` or `error`. |

Both keys are masked in the user interface and are passed to the runtime in
memory. The add-on never writes a key to its data volume, never logs one, and
never includes one in diagnostics or discovery messages.

Each key is checked against its digest before the radio transmits anything. A
mismatch stops startup; it does not fall back to any other key.

### Where the keys and digests come from

They are exported once from the machine that commissioned the units, where
they are protected by that operator's Windows account and cannot be read
anywhere else. Run the export tool there, type the values into this form, and
close the terminal. The tool prints each value once and writes nothing to disk.

### Security note

Add-on options are stored by the Supervisor as plain text on the Home
Assistant data partition. Anyone with physical access to the SD card can read
the keys from it. This is the deliberate trade for unattended restart after a
power cut: a machine that can start by itself must hold whatever it needs to
start. If that trade is wrong for your installation, the alternative is a
passphrase typed at every start, which gives up automatic recovery.

## Durable stores

Each context keeps a durable security store holding its frame counters, replay
floors, key epoch and identity. The add-on expects them at:

```
/data/stores/ctx0/hardware_gate_v1/runs/<run-id>/...
/data/stores/ctx1/hardware_gate_v2/runs/<run-id>/...
```

These stores must be migrated from the commissioning machine, not recreated.
Frame counters only ever move forward: a store that goes backwards is treated
as a rollback and the service fails closed rather than transmitting with a
counter that may already have been used.

For the same reason the stores are excluded from Home Assistant backups.
Restoring a backup taken days ago would otherwise reinstate old counters. Keep
your own copy of the stores if you want a recovery path, and understand that
restoring one is a deliberate act with protocol consequences.

## Restart behaviour

Turn on **Watchdog** in the add-on's own panel so the Supervisor restarts the
service if it exits unexpectedly. With `boot: auto` the add-on also starts with
Home Assistant.

Not every stop is a crash to recover from. Protocol and security faults latch
in the add-on's state directory, and a restart does not clear them — that is
deliberate. A latched fault means something happened that needs a person to
look at it, and restarting into the same radio state could spend counters on a
run that cannot finish.

## Troubleshooting

**`dongle_absent`** — the dongle is not plugged in, or its USB serial does not
match the pinned one. The add-on identifies the dongle by vendor, product and
serial number, not by device path, so a different dongle will not be used by
accident.

**`serial_open_failed`** — the device was found but could not be opened.
Usually another process holds it. Only one owner of the dongle may run at a
time; the add-on enforces this with a lock.

**Key digest mismatch** — the key typed into the form does not match the one
the store expects. Re-run the export tool and check for a transcription error.

**Service will not leave a blocked state** — read the add-on log for the
latched reason before restarting. See the operations runbook in the main
repository.
