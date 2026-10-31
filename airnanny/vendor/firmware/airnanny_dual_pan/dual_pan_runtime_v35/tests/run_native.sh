#!/bin/sh
# Builds and runs every native offline suite, with and without sanitizers.
#
# This existed only as commands typed by hand through phases 1.1 to 1.5, which
# is not evidence: a corpus nobody else can rebuild proves nothing, and the one
# detail that mattered most -- how the frozen V25 transport is linked beside the
# new one -- lived in a sentence in the README instead of in a build line.
#
# No COM, no RF, no flash, no cryptography, no keys, no network.
#
# Usage: sh tests/run_native.sh            (from the runtime root)
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
V25=$(cd "$ROOT/../ctx1_rx_admission_v25" && pwd)
OUT=$ROOT/build
mkdir -p "$OUT"

CC=${CC:-gcc}
# -Wmisleading-indentation is off deliberately. src/rejoin_transport.c keeps
# V25's dense single-line style so the two files stay diffable line by line,
# which is what the transport equivalence proof rests on; reformatting it to
# satisfy this one warning would cost that and prove nothing. Every other
# warning is an error.
WARN="-std=c11 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-misleading-indentation"
# No SDK and no CMSIS here. These suites run on the build host, not on the
# part, and tests/ holds the type shims (nrf_radio.h and friends) that let the
# driver headers compile for x86. Reaching into the SDK's nrfx headers instead
# drags in Cortex-M register definitions and IRQn_Type, which is how a host
# build ends up either broken or quietly wrong about word size.
INC="-I$ROOT/include -I$ROOT/src -I$ROOT/tests -I$ROOT/radio_driver \
-I$ROOT/radio_driver/mac_features"
HOSTDEF="-DASSOC_HOST_TEST"

# The frozen V25 transport is linked into the equivalence binary beside the new
# one. Its external names are redefined at compile time, so the V25 source file
# itself is never edited: the comparison is against the shipped bytes of the
# implementation that has hardware proof, not against a copy of it.
V25_RENAME="\
-Dmanagement_parse=v25_management_parse \
-Dmanagement_resume=v25_management_resume \
-Dmanagement_tx=v25_management_tx \
-Dmanagement_control=v25_management_control \
-Dmanagement_done=v25_management_done \
-Dmanagement_auto_poll=v25_management_auto_poll \
-Dmanagement_beacon=v25_management_beacon \
-Dmanagement_observe=v25_management_observe \
-Dmanagement_tick=v25_management_tick \
-Dcommission_observe=v25_commission_observe \
-Dcommission_stop=v25_commission_stop \
-Drecovery_name=v25_recovery_name \
-Dcommission_name=v25_commission_name \
-Dmanagement_class=v25_management_class"

run() {
    name=$1; shift
    printf '%-28s ' "$name"
    "$OUT/$name.exe" > "$OUT/$name.log" 2>&1 || true
    tail -1 "$OUT/$name.log"
}

# --- suites over the dual-PAN layer alone -------------------------------------
for s in test_dual_admit test_dual_sched test_dual_records; do
    $CC $WARN $INC $HOSTDEF -O1 -o "$OUT/$s.exe" \
        "$ROOT/tests/$s.c" "$ROOT/src/dual_context.c" "$ROOT/src/dual_admit.c" \
        "$ROOT/src/dual_identity.c" "$ROOT/src/dual_sched.c" "$ROOT/src/dual_records.c"
    run "$s"
    $CC $WARN $INC $HOSTDEF -O1 -fsanitize=address,undefined \
        -o "$OUT/$s.san.exe" \
        "$ROOT/tests/$s.c" "$ROOT/src/dual_context.c" "$ROOT/src/dual_admit.c" \
        "$ROOT/src/dual_identity.c" "$ROOT/src/dual_sched.c" "$ROOT/src/dual_records.c"
    run "$s.san"
done

# --- the two equivalence proofs ----------------------------------------------
$CC $WARN $INC $HOSTDEF -O1 -o "$OUT/test_v25_equivalence.exe" \
    "$ROOT/tests/test_v25_equivalence.c" "$ROOT/src/dual_context.c" \
    "$ROOT/src/dual_admit.c" "$ROOT/src/dual_identity.c" \
    -I"$V25/include" "$V25/src/assoc_filter.c"
run test_v25_equivalence

# The frozen unit is compiled against V25's OWN headers and nothing of V26's.
# Mixing the two include paths lets the rename macros rewrite V26's
# declarations as well, so the prefixed name ends up declared with V26's
# signature and defined with V25's -- the compiler then reports a conflict that
# looks like a bug in the frozen code and is really a bug in this build line.
#
# -Werror is dropped for this one object as well. V25's dense single-line style
# trips -Wmisleading-indentation, and its source is frozen evidence: the right
# response to a warning in it is to not edit it, not to silence the warning by
# rewriting the file.
INC25="-I$V25/include -I$V25/src -I$ROOT/tests"
$CC -std=c11 -Wall $INC25 $HOSTDEF -O1 -c -o "$OUT/v25_transport.o" \
    $V25_RENAME "$V25/src/rejoin_transport.c" 2>/dev/null
$CC $WARN $INC $HOSTDEF -O1 -o "$OUT/test_transport_equivalence.exe" \
    "$ROOT/tests/test_transport_equivalence.c" "$ROOT/src/rejoin_transport.c" \
    "$ROOT/src/dual_identity.c" "$ROOT/src/permit_binding.c" "$ROOT/src/key_gate.c" \
    "$ROOT/src/assoc.c" "$OUT/v25_transport.o"
run test_transport_equivalence

# --- V27's one change: a clean poll miss is retried, not terminal ------------
for san in '' '-fsanitize=address,undefined'; do
    case "$san" in "") tag= ;; *) tag=.san ;; esac
    $CC $WARN $INC $HOSTDEF -O1 $san -o "$OUT/test_poll_misses$tag.exe" \
        "$ROOT/tests/test_poll_misses.c" "$ROOT/src/rejoin_transport.c" \
        "$ROOT/src/dual_identity.c" "$ROOT/src/permit_binding.c" "$ROOT/src/key_gate.c" \
        "$ROOT/src/assoc.c" "$OUT/v25_transport.o"
    run "test_poll_misses$tag"
done

FIXTURE_SRC="$ROOT/src/assoc.c $ROOT/src/assoc_protocol.c $ROOT/src/permit_binding.c \
$ROOT/src/key_gate.c $ROOT/src/rejoin_transport.c $ROOT/src/dual_context.c \
$ROOT/src/dual_admit.c $ROOT/src/dual_identity.c $ROOT/src/dual_sched.c \
$ROOT/src/dual_records.c $ROOT/src/assoc_filter.c"

# --- V28's one change: a chain frame's lost ACK is retried at the MAC --------
# Built against the real src/main.c through firmware_cli.c, so the lifecycle,
# CCA backoff and watchdog under test are the image's own.
for san in '' '-fsanitize=address,undefined'; do
    case "$san" in "") tag= ;; *) tag=.san ;; esac
    $CC $WARN -Wno-unused-function $INC $HOSTDEF -O1 $san -o "$OUT/test_mac_retry$tag.exe" \
        "$ROOT/tests/test_mac_retry.c" $FIXTURE_SRC
    run "test_mac_retry$tag"
done

# --- parser fuzz --------------------------------------------------------------
$CC $WARN $INC $HOSTDEF -O1 -fsanitize=address,undefined \
    -o "$OUT/fuzz_dual_records.exe" \
    "$ROOT/tests/fuzz_dual_records.c" "$ROOT/src/dual_records.c" \
    "$ROOT/src/dual_context.c" "$ROOT/src/dual_identity.c" "$ROOT/src/dual_sched.c"
run fuzz_dual_records

# --- host fixtures the Python suites drive ------------------------------------
# firmware_cli.exe compiles the real src/main.c with a fake radio, so the Python
# suites exercise the dispatcher itself rather than a model of it. -Wno-unused-
# function is needed only because the mock header defines PIB setters that the
# dual runtime no longer calls: under DUAL_PAN_GATE the driver's destination
# filter is replaced, so the PIB takes no part in admission.
$CC $WARN -Wno-unused-function $INC $HOSTDEF -O1 -o "$OUT/firmware_cli.exe" \
    "$ROOT/tests/firmware_cli.c" $FIXTURE_SRC
echo "firmware_cli.exe            built"

$CC $WARN -Wno-unused-function $INC $HOSTDEF -O1 -o "$OUT/scan_replay.exe" \
    "$ROOT/tests/scan_replay.c" $FIXTURE_SRC
echo "scan_replay.exe             built"

echo "native suites complete; no hardware was touched"
