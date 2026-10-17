# AirNanny Dual-PAN — Home Assistant add-on repository

Home Assistant add-on that bridges two AirNanny A7 units to MQTT over a single
nRF52840 dongle, with each unit on its own Zigbee PAN.

## Install

Home Assistant add-ons are not installed through HACS. Add this repository to
the add-on store instead:

1. **Settings → Add-ons → Add-on Store**
2. the three-dot menu, top right → **Repositories**
3. paste `https://github.com/mrkotee/breeze_control_addon` and select **Add**
4. install **AirNanny Dual-PAN Bridge** from the list

Requires Home Assistant OS or Supervised on `aarch64`, and the Mosquitto
broker add-on installed and started.

## Add-ons

| Add-on | Description |
| --- | --- |
| [AirNanny Dual-PAN Bridge](airnanny/) | Two A7 units bridged to MQTT; state published only from confirmed device state. |

Configuration, the key export procedure and troubleshooting are in the
[add-on documentation](airnanny/DOCS.md).

## How the image is built

The add-on is pulled, not built on your machine. Building locally makes
Supervisor fetch its own buildx helper image from Docker Hub first, which
fails outright on hosts that cannot reach that registry — before this add-on's
Dockerfile is read at all.

Instead this repository's workflow builds `linux/arm64` and publishes to
`ghcr.io/mrkotee/breeze_control_addon-aarch64`, the same registry Home
Assistant already pulls itself from. Supervisor requests the tag matching the
`version` in `airnanny/config.yaml`, so a version that was never built fails
to pull rather than quietly running an older image.

## What is in this repository

`airnanny/vendor/` holds the runtime assembled from the `breeze_control`
project at release time, with a SHA-256 manifest recording exactly what went
in. The layout under `vendor/` mirrors that project because the frozen
firmware host code derives its pinned durable-store paths from its own
location on disk.

No key, credential or other secret material is published here. Network keys
are supplied by the operator through the add-on's own configuration.
