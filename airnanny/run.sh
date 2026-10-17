#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -euo pipefail

FIRMWARE="${AIRNANNY_HOME}/firmware/airnanny_dual_pan"
HOST="${AIRNANNY_HOME}/host/airnanny2mqtt"

# ---------------------------------------------------------------------------
# Durable stores
#
# The frozen firmware host code pins each context's store to a path derived
# from its own __file__, and ContextLedger(hardware=True) refuses to write
# anywhere else. Rather than edit that reviewed guard, the two .local
# directories it expects are linked onto the add-on's persistent volume, so
# the pinned paths resolve into /data without a single frozen line changing.
# ---------------------------------------------------------------------------
link_store() {
    local milestone="$1" target="$2"
    mkdir -p "${target}"
    if [ -e "${FIRMWARE}/${milestone}/.local" ] && [ ! -L "${FIRMWARE}/${milestone}/.local" ]; then
        bashio::exit.nok "unexpected real directory at ${milestone}/.local in the image"
    fi
    ln -sfn "${target}" "${FIRMWARE}/${milestone}/.local"
}

mkdir -p /data/state

# Durable stores are staged in /share because an add-on's data volume is not
# reachable from the shares an operator can write to. The import is
# create-only: a context that already has a store is never touched, so this
# step cannot be the thing that loses counters.
if [ -d /share/airnanny_stores ]; then
    python3 "${HOST}/tools/import_stores.py" \
        --staging /share/airnanny_stores --target /data/stores \
        || bashio::exit.nok "staged store import failed; see the message above"
fi

link_store "hardware_commissioning_v7" "/data/stores/ctx0"
link_store "second_a7_provisioning_v1" "/data/stores/ctx1"

# ---------------------------------------------------------------------------
# Network keys
#
# Supplied by the operator through the add-on configuration and passed to the
# runtime in memory only. Nothing here writes a key to /data, echoes it, or
# puts it on the command line. The runtime verifies each one against its
# sha256(secret_ref || key) digest and fails closed on a mismatch.
# ---------------------------------------------------------------------------
for slot in 0 1; do
    if bashio::config.is_empty "ctx${slot}_network_key"; then
        bashio::exit.nok "ctx${slot}_network_key is not set; see the add-on documentation"
    fi
    if bashio::config.is_empty "ctx${slot}_key_sha256"; then
        bashio::exit.nok "ctx${slot}_key_sha256 is not set; the key cannot be verified"
    fi
done

export AIRNANNY_CTX0_KEY AIRNANNY_CTX1_KEY
export AIRNANNY_CTX0_KEY_SHA256 AIRNANNY_CTX1_KEY_SHA256
AIRNANNY_CTX0_KEY="$(bashio::config 'ctx0_network_key')"
AIRNANNY_CTX1_KEY="$(bashio::config 'ctx1_network_key')"
AIRNANNY_CTX0_KEY_SHA256="$(bashio::config 'ctx0_key_sha256')"
AIRNANNY_CTX1_KEY_SHA256="$(bashio::config 'ctx1_key_sha256')"

# ---------------------------------------------------------------------------
# Broker
#
# Taken from the Supervisor mqtt service, so the installed Mosquitto's
# credentials are never copied into this repository or the add-on options.
# ---------------------------------------------------------------------------
if ! bashio::services.available "mqtt"; then
    bashio::exit.nok "no MQTT service is available; install and start Mosquitto first"
fi

MQTT_HOST="$(bashio::services 'mqtt' 'host')"
MQTT_PORT="$(bashio::services 'mqtt' 'port')"

# The runtime refuses plaintext MQTT to anything but a loopback address, and
# it is right to: the rule exists so credentials and commands cannot cross a
# network in the clear. A broker named core-mosquitto is not loopback, even
# though its traffic never leaves this machine.
#
# Rather than weaken that rule or point the service at an address that merely
# behaves like loopback, the add-on shares the host's network namespace and
# speaks to the port the broker publishes there. Then it really is loopback,
# and the check passes because the thing it checks for is true. Any other
# broker keeps the existing requirement of explicit opt-in and verified TLS.
if [ "${MQTT_HOST}" = "core-mosquitto" ] || [ "${MQTT_HOST}" = "172.30.33.0" ]; then
    if python3 -c "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1])), 3).close()" \
            "${MQTT_PORT}" 2>/dev/null; then
        bashio::log.info "Local broker reached on loopback port ${MQTT_PORT}"
        MQTT_HOST=127.0.0.1
    else
        bashio::exit.nok "the local broker does not publish port ${MQTT_PORT} on the host; enable it under the Mosquitto add-on's Network settings"
    fi
fi
export AIRNANNY_MQTT_USERNAME AIRNANNY_MQTT_PASSWORD
AIRNANNY_MQTT_USERNAME="$(bashio::services 'mqtt' 'username')"
AIRNANNY_MQTT_PASSWORD="$(bashio::services 'mqtt' 'password')"

FIRMWARE_VERSION="$(bashio::config 'firmware_version')"
export AIRNANNY_LOG_LEVEL
AIRNANNY_LOG_LEVEL="$(bashio::config 'log_level')"

# Normally empty. A latched fault is cleared by writing its reason here
# exactly, which the service then checks against what it actually latched --
# so this cannot clear a different fault, and it cannot clear one that needs
# a person to decide what happened.
export AIRNANNY_ACKNOWLEDGE_FAULT
if bashio::config.has_value 'acknowledge_fault'; then
    AIRNANNY_ACKNOWLEDGE_FAULT="$(bashio::config 'acknowledge_fault')"
    bashio::log.warning "Operator acknowledgement present for: ${AIRNANNY_ACKNOWLEDGE_FAULT}"
else
    AIRNANNY_ACKNOWLEDGE_FAULT=""
fi

cd "${HOST}"

# A placement survey instead of the bridge. It listens, transmits nothing,
# and touches neither the durable stores nor the service state, so it can be
# run between attempts without leaving anything behind. The add-on stops
# afterwards; set this back to 0 to run the bridge again.
SURVEY_SECONDS="$(bashio::config 'survey_seconds')"
if [ "${SURVEY_SECONDS}" -gt 0 ] 2>/dev/null; then
    bashio::log.warning "Survey mode: listening for ${SURVEY_SECONDS}s, the bridge will not start"
    exec python3 tools/survey_radio.py --seconds "${SURVEY_SECONDS}"
fi

bashio::log.info "Starting AirNanny dual-PAN bridge (V${FIRMWARE_VERSION}) against ${MQTT_HOST}:${MQTT_PORT}"
exec python3 tools/run_radio_service.py \
    --firmware-version "${FIRMWARE_VERSION}" \
    --mqtt-host "${MQTT_HOST}" \
    --mqtt-port "${MQTT_PORT}"
