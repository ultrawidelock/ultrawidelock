#!/usr/bin/env bash
# Portable host suites for module contracts and the credential core.
#
# Eleven independent suites: each one compiles its own binary from the shipping
# sources, runs it, and throws the binary away. Nothing here reads anything
# another block wrote, so they are run CONCURRENTLY -- see the driver at the
# bottom of this file for how, and why the log still comes out in the order
# written here.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CRED="$ROOT/modules/ultrawidelock_cred"
ULTRAWIDELOCK_PORT_INC="$ROOT/modules/ultrawidelock_port/include"
UWB_INC="$ROOT/modules/ultrawidelock_uwb/include"
DW3000_INC="$ROOT/modules/ultrawidelock_dw3000/include"

# Each block below is exactly the commands that were here before, in the same
# order, wrapped in a function so the driver can start them all at once. The
# leading `echo` stays INSIDE its block: the blank line is part of that suite's
# output, and keeping it here is what makes the concatenated log byte-identical
# to the sequential one it replaces.

blk_port_headers() {
	echo "== host: port headers unit test =="
	BIN="$(mktemp -t ultrawidelock_port_headers.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-I "$ULTRAWIDELOCK_PORT_INC" -I "$UWB_INC" -I "$CRED/include" -I "$DW3000_INC" \
		"$HERE/test_port_headers.c" -o "$BIN"
	"$BIN"
	rm -f "$BIN"
}

blk_crypto() {
	echo
	echo "== host: ultrawidelock_crypto key-schedule KAT =="
	CBIN="$(mktemp -t ultrawidelock_crypto_kat.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-I "$CRED/include" -I "$CRED/src" \
		"$HERE/test_ultrawidelock_crypto.c" \
		"$CRED/src/ultrawidelock_hash.c" "$CRED/src/ultrawidelock_crypto.c" "$CRED/src/ultrawidelock_advtag.c" \
		"$HERE/ultrawidelock_prim_host.c" -o "$CBIN"
	"$CBIN"
	rm -f "$CBIN"
}

blk_assert_ec() {
	echo
	echo "== host: ultrawidelock_assert_ec P-256 binder =="
	ECBIN="$(mktemp -t ultrawidelock_assert_ec.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-I "$CRED/include" -I "$CRED/src" \
		"$HERE/test_ultrawidelock_assert_ec.c" \
		"$CRED/src/ultrawidelock_assert.c" "$CRED/src/ultrawidelock_assert_ec.c" "$CRED/src/ultrawidelock_hash.c" \
		"$HERE/ultrawidelock_prim_host.c" -o "$ECBIN"
	"$ECBIN"
	rm -f "$ECBIN"
}

blk_apdu() {
	echo
	echo "== host: ultrawidelock_apdu wire-codec KAT =="
	ABIN="$(mktemp -t ultrawidelock_apdu_kat.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-I "$CRED/include" -I "$CRED/src" \
		"$HERE/test_ultrawidelock_apdu.c" "$CRED/src/ultrawidelock_apdu.c" -o "$ABIN"
	"$ABIN"
	rm -f "$ABIN"
}

blk_device() {
	echo
	echo "== host: ultrawidelock_device initiator codec + crypto KAT =="
	DBIN="$(mktemp -t ultrawidelock_device.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra -DULTRAWIDELOCK_DEVICE_HAVE_EC \
		-I "$CRED/include" -I "$CRED/src" \
		"$HERE/test_ultrawidelock_device.c" \
		"$CRED/src/ultrawidelock_device.c" "$CRED/src/ultrawidelock_device_apdu.c" \
		"$CRED/src/ultrawidelock_apdu.c" "$CRED/src/ultrawidelock_crypto.c" "$CRED/src/ultrawidelock_hash.c" \
		"$HERE/ultrawidelock_prim_host.c" -o "$DBIN"
	"$DBIN"
	rm -f "$DBIN"
}

blk_ble_central() {
	echo
	echo "== host: ultrawidelock_ble_central device-transport decoders =="
	BCBIN="$(mktemp -t ultrawidelock_ble_central.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-I "$CRED/include" \
		"$HERE/test_ultrawidelock_ble_central.c" "$CRED/src/ultrawidelock_ble_central.c" -o "$BCBIN"
	"$BCBIN"
	rm -f "$BCBIN"
}

blk_stepup() {
	echo
	echo "== host: ultrawidelock_stepup Access-Document codec + section 7.4 verifier KAT =="
	SBIN="$(mktemp -t ultrawidelock_stepup_kat.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-I "$HERE" -I "$CRED/include" -I "$CRED/src" \
		"$HERE/test_ultrawidelock_stepup.c" \
		"$CRED/src/ultrawidelock_stepup.c" "$CRED/src/ultrawidelock_stepup_wire.c" \
		"$CRED/src/ultrawidelock_stepup_parse.c" "$CRED/src/ultrawidelock_tlv.c" \
		"$CRED/src/ultrawidelock_hash.c" "$CRED/src/ultrawidelock_crypto.c" \
		"$HERE/ultrawidelock_prim_host.c" -o "$SBIN"
	"$SBIN"
	rm -f "$SBIN"
}

blk_prov() {
	echo
	echo "== host: ultrawidelock_prov identity/trust KAT =="
	PBIN="$(mktemp -t ultrawidelock_prov_kat.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-I "$CRED/include" -I "$CRED/src" \
		"$HERE/test_ultrawidelock_prov.c" "$CRED/src/ultrawidelock_prov.c" -o "$PBIN"
	"$PBIN"
	rm -f "$PBIN"
}

blk_lat() {
	echo
	echo "== host: ultrawidelock_lat walk-up trace (gate on + gate off) =="
	TBIN="$(mktemp -t ultrawidelock_lat.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-D_POSIX_C_SOURCE=200809L -DULTRAWIDELOCK_PORT_HOST -DCONFIG_ULTRAWIDELOCK_LAT_TRACE=1 \
		-I "$CRED/include" -I "$ULTRAWIDELOCK_PORT_INC" \
		"$HERE/test_ultrawidelock_lat.c" "$CRED/src/ultrawidelock_lat.c" -o "$TBIN"
	"$TBIN"
	cc -std=c11 -O1 -Wall -Wextra \
		-D_POSIX_C_SOURCE=200809L -DULTRAWIDELOCK_PORT_HOST \
		-I "$CRED/include" -I "$ULTRAWIDELOCK_PORT_INC" \
		"$HERE/test_ultrawidelock_lat.c" "$CRED/src/ultrawidelock_lat.c" -o "$TBIN"
	"$TBIN"
	rm -f "$TBIN"
}

blk_reader() {
	echo
	echo "== host: ultrawidelock_reader engine walk-up (scripted phone) =="
	RBIN="$(mktemp -t ultrawidelock_reader.XXXXXX)"
	# The step-up phase is built in (CONFIG_ULTRAWIDELOCK_CRED_STEPUP): section G walks
	# an unknown credential through the Access Document it is learned from. The
	# first build also carries the bench one-shot (the ESP32 shape), the second
	# only the learn path (the DWM3001CDK shape).
	cc -std=c11 -O1 -Wall -Wextra \
		-Wno-unused-variable -Wno-unused-function \
		-D_POSIX_C_SOURCE=200809L -DULTRAWIDELOCK_PORT_HOST \
		-DCONFIG_ULTRAWIDELOCK_CRED_DEV_TRUST=1 -DCONFIG_ULTRAWIDELOCK_CRED_STEPUP=1 \
		-DCONFIG_ULTRAWIDELOCK_CRED_STEPUP_BENCH=1 \
		-I "$CRED/include" -I "$CRED/src" -I "$ULTRAWIDELOCK_PORT_INC" \
		"$HERE/test_ultrawidelock_reader.c" \
		"$CRED/src/ultrawidelock_reader.c" "$CRED/src/ultrawidelock_apdu.c" \
		"$CRED/src/ultrawidelock_crypto.c" "$CRED/src/ultrawidelock_hash.c" \
		"$CRED/src/ultrawidelock_prov.c" "$CRED/src/ultrawidelock_stepup.c" \
		"$CRED/src/ultrawidelock_stepup_wire.c" "$CRED/src/ultrawidelock_stepup_parse.c" \
		"$CRED/src/ultrawidelock_tlv.c" \
		"$HERE/ultrawidelock_prim_host.c" "$ROOT/tests/host/port/osal_host.c" -o "$RBIN"
	"$RBIN"
	cc -std=c11 -O1 -Wall -Wextra \
		-Wno-unused-variable -Wno-unused-function \
		-D_POSIX_C_SOURCE=200809L -DULTRAWIDELOCK_PORT_HOST \
		-DCONFIG_ULTRAWIDELOCK_CRED_STEPUP=1 \
		-I "$CRED/include" -I "$CRED/src" -I "$ULTRAWIDELOCK_PORT_INC" \
		"$HERE/test_ultrawidelock_reader.c" \
		"$CRED/src/ultrawidelock_reader.c" "$CRED/src/ultrawidelock_apdu.c" \
		"$CRED/src/ultrawidelock_crypto.c" "$CRED/src/ultrawidelock_hash.c" \
		"$CRED/src/ultrawidelock_prov.c" "$CRED/src/ultrawidelock_stepup.c" \
		"$CRED/src/ultrawidelock_stepup_wire.c" "$CRED/src/ultrawidelock_stepup_parse.c" \
		"$CRED/src/ultrawidelock_tlv.c" \
		"$HERE/ultrawidelock_prim_host.c" "$ROOT/tests/host/port/osal_host.c" -o "$RBIN"
	"$RBIN"
	rm -f "$RBIN"
}

blk_ranging() {
	echo
	echo "== host: ultrawidelock_ranging M1-M4 session glue =="
	GBIN="$(mktemp -t ultrawidelock_ranging.XXXXXX)"
	cc -std=c11 -O1 -Wall -Wextra \
		-D_POSIX_C_SOURCE=200809L -DULTRAWIDELOCK_PORT_HOST -DCONFIG_ULTRAWIDELOCK_LAT_TRACE=1 \
		-I "$CRED/include" -I "$CRED/src" -I "$ULTRAWIDELOCK_PORT_INC" -I "$UWB_INC" \
		"$HERE/test_ultrawidelock_ranging.c" \
		"$CRED/src/ultrawidelock_ranging.c" "$CRED/src/ultrawidelock_crypto.c" \
		"$CRED/src/ultrawidelock_hash.c" "$CRED/src/ultrawidelock_lat.c" \
		"$HERE/ultrawidelock_prim_host.c" -o "$GBIN"
	"$GBIN"
	rm -f "$GBIN"
}

# The remaining host suites exercise ESP-owned sources against ESP fakes.
blk_esp32() {
	bash "$ROOT/tests/ports/esp32/run.sh"
}

# ---- the driver -------------------------------------------------------------
# Start every block at once, each writing to its own file, then replay the files
# in the order the blocks are listed above.
#
# WHY THE CAPTURE. Interleaving is not cosmetic here. scripts/test-runner.sh
# counts this suite's result by matching `  ok ` and `  FAIL ` rows in its
# output, and it replays a failing suite's FAIL rows under the suite's own
# heading. Blocks writing to one stream concurrently tear each other's lines in
# half, which loses rows from the count and makes the replayed failure
# unreadable. Buffering each block whole and concatenating in list order costs
# nothing and leaves the log byte-identical to the sequential run.
#
# WHY NOT `wait -n` / A JOB POOL. All of them together are eleven compiles; the
# machine has more cores than that is worth managing, and scripts/test-runner.sh
# is already running the other suites alongside. A pool would add a scheduler to
# save nothing.
#
# HOW A FAILURE STILL FAILS. `set -e` does not reach into a background job, so
# each block's status is written to its own file and checked after the wait. The
# suite exits nonzero if ANY block did -- and every block's output is printed
# first, so a failure that happened in parallel with a pass still shows both.
BLOCKS=(
	blk_port_headers blk_crypto blk_assert_ec blk_apdu blk_device
	blk_ble_central blk_stepup blk_prov blk_lat blk_reader blk_ranging
	blk_esp32
)

work="$(mktemp -d -t ultrawidelock_shared.XXXXXX)"
pids=""

# The blocks are compilers. Interrupting this script while twelve of them are
# in flight must not return the prompt and leave the machine busy, so they are
# ended with it rather than orphaned -- the same reason scripts/test-runner.sh
# kills its suite trees instead of just exiting.
cleanup() {
	local p
	for p in $pids; do
		kill "$p" 2>/dev/null || true
	done
	rm -rf "$work"
}
trap cleanup EXIT
trap 'cleanup; trap - INT; kill -INT $$' INT
trap 'cleanup; trap - TERM; kill -TERM $$' TERM

for b in "${BLOCKS[@]}"; do
	# `|| echo $? >rc` rather than `set -e`: the block runs in a subshell, and
	# its status has to survive as data for the loop below.
	{
		rc=0
		"$b" >"$work/$b.out" 2>&1 || rc=$?
		printf '%s' "$rc" >"$work/$b.rc"
	} &
	pids="$pids $!"
done
wait

failed=0
for b in "${BLOCKS[@]}"; do
	cat "$work/$b.out"
	[ "$(cat "$work/$b.rc" 2>/dev/null || echo 1)" = 0 ] || failed=1
done
exit "$failed"
