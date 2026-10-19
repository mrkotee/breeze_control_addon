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
| `poll_interval_ms` | How often the service loop runs. Default `20`. See *CPU use* below. |

The keys are **not** masked in the form, and they are **not** private to this
add-on. Both facts are the platform's, not this add-on's, and you should know
them before typing a key in:

- Masking is only applied to options declared as passwords, and these are
  declared as hex strings instead. Supervisor sends a password-typed option to
  an online breach-check service before saving it, and where that service
  cannot be reached the save fails with an unexplained error. A hex pattern
  also rejects a truncated paste, which the password type never did.
- Supervisor stores every add-on option as plain text on the data partition,
  and that file is included in Home Assistant backups. Your network keys are
  therefore in every backup you take, and readable by anyone holding the SD
  card. Treat backups of this system as key material.

What the add-on itself does with them is narrower: the keys are read into
memory at startup, verified against their digests, and used to construct the
context ledgers. The add-on never writes a key to its own data volume, never
logs one, and never puts one in a diagnostics or discovery message.

Each key is checked against its digest before the radio transmits anything. A
mismatch stops startup; it does not fall back to any other key.

### Where the keys and digests come from

They are exported once from the machine that commissioned the units, where
they are protected by that operator's Windows account and cannot be read
anywhere else. Run the export tool there, type the values into this form, and
close the terminal. The tool prints each value once and writes nothing to disk.

### Security note

This is the deliberate trade for unattended restart after a power cut: a
machine that can start by itself must hold whatever it needs to start. If
that trade is wrong for your installation, the alternative is a passphrase
typed at every start, which gives up automatic recovery.

## Clearing a latched fault

Some faults stop the service and are **not** cleared by restarting it. That
is deliberate: a latch means something happened that needs a person, and
restarting into the same radio state could spend counters on a run that
cannot finish.

When the service is latched it prints the reason, a summary of what the
failed attempt actually did, and whether acknowledging it can clear it. To
clear one, write its reason into **Acknowledge a latched fault** exactly as
printed, then start the add-on.

**Empty that field again afterwards.** An acknowledgement is spent on the run
it is used for, so leaving it in place does not silently clear every future
latch — but a field left populated is a standing instruction, and the point
of a latch is that a returning fault stops for a person.

Faults that need judgement rather than acknowledgement — a durable store that
moved backwards, a device that left the network, an interrupted secured
exchange — stay latched however exactly they are named. Read the operations
runbook in the main repository before going further with those.

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

For the same reason the stores are excluded from Home Assistant backups, and
so is the record of how far their counters had got. Restoring a backup taken
days ago would otherwise reinstate old counters, and reinstating the record
alongside them would hide that it had happened.

**Delete the staging directory once the import is confirmed.** A copy left in
`/share/airnanny_stores` is a snapshot of the counters as they were on the day
you made it. If this add-on's data volume is ever emptied — a reinstall, a
replaced card — that stale copy is what the next start will import, putting
the counters back to that day with nothing left to notice it. The copy is of
no further use once the first start has reported `imported`.

## Cards

Each unit publishes two entities that Home Assistant draws as proper cards,
instead of leaving you with eight unrelated tiles.

**Fan** is the ventilation: on or off, a speed dial over the seven steps the
unit actually has, and the air source as a preset.

**Thermostat** is the heater: a target temperature between 10 and 30 degrees
in half-degree steps.

| Control | Card | Values |
| --- | --- | --- |
| Power | both | on, off |
| Speed | fan | 1-7, shown as a dial |
| Air source | fan, thermostat | `intake`, `mixed`, `recirc` |
| Mode | thermostat | `off`, `heat` |
| Target temperature | thermostat | 10-30, in halves |

They overlap on power and air source on purpose: the appliance has one
switch, and either card should be usable on its own. The individual
entities all remain as well -- hide the ones you do not want from the
device page.

Three things behave the way the rest of this bridge does rather than the way
these cards usually do.

Nothing moves until the unit confirms it. Set a speed and the dial stays
where it was until the unit reports the new one. That is deliberate: a card
here shows what the appliance is doing, never what it was asked to do.

There is no `fan_only` mode on the thermostat. Home Assistant sends the mode
to one topic, and on this protocol turning the heater off is a different
command from powering the unit on, so a `fan_only` selection would have had
to silently do nothing. Turn the heater off with the **Temperature Off**
button instead; the unit then reports no target and the dial shows none,
while the fan keeps running.

There is no current temperature, because decoding an ambient reading from
this protocol has not been done. The thermostat shows a target without a
measured value, which is what Home Assistant does for any thermostat that
reports no sensor.

## What the bridge reports about itself

Each A7 appears as its own device, and its entities say whether that unit is
online, stale or unavailable. They cannot say *why* the bridge as a whole is
not working: a broker outage, an unplugged dongle, a durable store that will
not load and a unit that has stopped talking all leave the same silence on a
device topic.

A separate **AirNanny Bridge** device answers that. It carries two diagnostic
sensors:

- **Degraded Reason** - `none` when everything is working, otherwise exactly
  one of `context_store_error`, `radio_unavailable`, `mqtt_unavailable`,
  `device_unavailable` or `device_stale`, worst first. A store that will not
  load outranks a missing dongle, which outranks a broker outage, which
  outranks anything the devices are doing.
- **Service State** - where the service itself is: `ACTIVE`, `RECOVERING`,
  `WAITING`, `BLOCKED` or `STOPPING`.

A command that failed is deliberately not an input to either. One refused or
unanswered command says nothing about whether a unit is reachable, and
marking it unavailable while its status messages keep arriving would be a lie
that Home Assistant would then act on.

Neither sensor ever carries key material. The full document behind them is
published retained on `airnanny/daemon/diagnostics/state` and additionally
reports the durable counter positions, which is what makes an unexpected
jump or a stalled counter visible.

## CPU use

The service loop drains the dongle, pumps MQTT and ticks the daemon on every
pass, and the tick decides what to publish by serialising each device's state
and comparing the bytes, so a pass costs real work whether or not anything
changed. At the original 5 ms that measured as about a fifth of a Raspberry
Pi 4 core while idle.

The default is now 20 ms, roughly a quarter of that. The deadlines this has
to stay inside are far away: a transmission is given 3000 ms to be answered
and a dropped dongle reopens after 2000 ms. Raising `poll_interval_ms` to 50
halves the cost again and delays a state update by at most another 30 ms,
which is not perceptible in Home Assistant. Values outside 1-200 ms are
refused rather than quietly clamped.

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
