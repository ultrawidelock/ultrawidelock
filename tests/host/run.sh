#!/usr/bin/env bash
#
# Build + run the full host test suite (correctness gate). Plain C, no NCS
# toolchain or hardware. Compiles our logic modules against tests/host/shim and
# runs every module suite. `make coverage` builds the same sources instrumented.
#
# Nine binaries get built here before the last one runs, and the compiles are
# the slow half, so each is a step of scripts/lib/ui.sh's progress display: on a
# terminal that is a bar and a percentage, everywhere else one line per step.
# The stage_* functions below are only that division -- every compile and every
# binary is the one that was here before, in the same order.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/host/sources.sh"
. "$ROOT/scripts/lib/ui.sh"

# One build root for the whole repo; the host suites own build/host.
OUT="${ULTRAWIDELOCK_BUILD_ROOT:-$ROOT/build}/host"
mkdir -p "$OUT"
# Belt to pl_start's braces: with no binary left from the last run, a stage that
# somehow reaches its run line without compiling has nothing stale to succeed
# against. A false PASS over a compile error is the one failure this suite must
# never have, so it is prevented twice.
# -r, not just -f: a SAN=1 run compiles with -g, and on macOS that leaves a
# host_test_*.dSYM DIRECTORY beside each binary. `rm -f` refuses a directory and
# exits non-zero, which under `set -e` turned "ran the sanitizer suite first"
# into a failing `make check` with no FAIL row to explain it.
rm -rf "$OUT"/host_test_*
# SAN=1: same suite rebuilt under ASan + UBSan (`make test-san`).
san_flags=
if [ -n "${SAN:-}" ]; then
  san_flags='-g -fsanitize=address,undefined -fno-sanitize-recover=all'
fi

# Shapes clang merely warns about and GCC rejects outright, promoted so a local
# run fails where CI would. `static ULTRAWIDELOCK_THREAD_STACK_DEFINE(...)` on a
# macro that already says static is the one that got through: every macOS run
# green, the Linux gate unable to compile the suite at all. Probed rather than
# assumed, because GCC errors on an unknown -Werror= name and does not need
# these anyway -- it already treats them as errors.
# A string, not an array, for the same reason san_flags is one: bash 3.2 is still
# what /usr/bin/env bash finds on a stock mac, and it treats an empty array under
# `set -u` as an unbound variable.
gcc_parity=
for f in -Werror=duplicate-decl-specifier; do
  if "${CC:-cc}" "$f" -x c -fsyntax-only /dev/null 2>/dev/null; then
    gcc_parity="$gcc_parity $f"
  fi
done

# --- target-only sources, separate small binaries --------------------------
# These compile production sources whose exported symbols the main binary
# already fakes (dw_rx_stub.c) or that need incompatible fakes, so they cannot
# join host_test. All of them run against recording doubles: branch logic and
# argument plumbing only, no hardware or crypto truth.
SRC="$ROOT/modules/ultrawidelock_uwb/src"
HOSTD="$ROOT/tests/host"

# -w: the shim intentionally leaves some args unused, and the in-tree modules are
# lint-gated by the real Zephyr build, not here. Errors still fail the build.
# -lm: test_ultrawidelock_door.c derives its expected chord lengths with cos/sqrt rather
# than restating the module's arithmetic. glibc keeps those in libm, so the link
# fails on Linux without this; on macOS libSystem already has them and the flag
# is a no-op, which is why this only ever breaks in CI.
stage_core_build() {
	# shellcheck disable=SC2086  # san_flags is a deliberate word-split flag list
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags "${DEFS[@]}" "${INCS[@]}" \
	   "${TEST_SRCS[@]}" "${SHIM_SRCS[@]}" "${UNIT_SRCS[@]}" \
	   -lm -o "$OUT/host_test"
}

stage_core_run() {
	# Quiet: suites assert, they don't need the UWB diag firehose on stdout (run
	# the binary directly, without ULTRAWIDELOCK_TEST_QUIET, to get it back).
	ULTRAWIDELOCK_TEST_QUIET=1 "$OUT/host_test"
}

# 1) uwb driver + shell (uwb_min/isr/rxdiag/cirdiag/selftest + ultrawidelock_shell) on
#    the drvfake radio + logfake zephyr surface.
stage_uwb_driver() {
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags \
		-DULTRAWIDELOCK_PORT_HOST -D_DEFAULT_SOURCE -DCONFIG_ULTRAWIDELOCK_CRED=1 -DCONFIG_ULTRAWIDELOCK_UWB_CIRDIAG=1 \
		-DCONFIG_ULTRAWIDELOCK_UWB_SELFTEST_DELAY_MS=250 \
		-DCONFIG_ULTRAWIDELOCK_UWB_LEDS=1 \
		-DCONFIG_ULTRAWIDELOCK_UWB_DEEPSLEEP=1 \
		-I"$HOSTD/shim" -I"$HOSTD" -I"$HOSTD/logfake" \
		-I"$ROOT/modules/ultrawidelock_uwb/include" \
		-I"$SRC/driver" -I"$SRC/ccc" -I"$SRC/fira" -I"$SRC/facade" -I"$ROOT/ports/zephyr/shell" \
		-I"$ROOT/modules/ultrawidelock_port/include" -I"$ROOT/modules/ultrawidelock_dw3000/include" \
		"$HOSTD/test.c" "$HOSTD/drv_main.c" \
		"$HOSTD/test_uwb_min.c" "$HOSTD/test_uwb_isr.c" "$HOSTD/test_uwb_rxdiag.c" \
		"$HOSTD/test_uwb_cirdiag.c" \
		"$HOSTD/test_uwb_selftest.c" "$HOSTD/test_ultrawidelock_shell.c" \
		"$HOSTD/shim/drvfake.c" \
		"$ROOT/tests/host/port/osal_host.c" \
		"$SRC/driver/uwb_min.c" "$SRC/driver/uwb_isr.c" "$SRC/driver/uwb_rxdiag.c" \
		"$SRC/driver/uwb_cirdiag.c" \
		"$SRC/driver/uwb_selftest.c" "$ROOT/ports/zephyr/shell/ultrawidelock_shell.c" \
		-o "$OUT/host_test_drv"
	ULTRAWIDELOCK_TEST_QUIET=1 "$OUT/host_test_drv"
}

# 2) The PSA primitive provider and portable CCC adapter over recording fakes
#    (psafake/). This checks the one target crypto boundary; AES truth remains
#    in the core suite's FIPS-197 reference provider.
stage_crypto_backends() {
	psa_flags=(-std=c11 -O1 -w -I"$HOSTD/psafake" -I"$ROOT/modules/ultrawidelock_uwb/include"
		-I"$SRC/ccc" -I"$ROOT/modules/ultrawidelock_cred/include")
	# ultrawidelock_seal.c belongs to this stage and not to the shared-core
	# binary: it calls the primitive seam, whose host provider is PSA-backed.
	# Its sources come from the role manifest, like every other
	# consumer's, so the host suite and the two ports cannot disagree.
	# seal + link + the WV2/WV3/WV4 codec the link speaks. Three roles, read
	# the same way every other consumer reads them.
	seal_srcs=()
	for _r in seal link anchor_msg; do
		while IFS= read -r _l; do
			_l="${_l%%#*}"
			_l="${_l#"${_l%%[![:space:]]*}"}"
			_l="${_l%"${_l##*[![:space:]]}"}"
			[ -n "$_l" ] && seal_srcs+=("$ROOT/$_l")
		done < "$ROOT/modules/ultrawidelock_anchor/roles/$_r.list"
	done
	# shellcheck disable=SC2086
	"${CC:-cc}" "${psa_flags[@]}" $san_flags \
		-I"$HOSTD" -I"$ROOT/modules/ultrawidelock_cred/include" \
		-I"$ROOT/modules/ultrawidelock_anchor/include" \
		"$HOSTD/test.c" "$HOSTD/test_psa_backends.c" "$HOSTD/psafake/psafake.c" \
		"$HOSTD/test_ultrawidelock_seal.c" "$HOSTD/test_ultrawidelock_link.c" \
		"${seal_srcs[@]}" \
		"$SRC/ccc/ccc_crypto_prim.c" \
		"$ROOT/modules/ultrawidelock_cred/src/ultrawidelock_prim_psa.c" \
		-o "$OUT/host_test_psa"
	"$OUT/host_test_psa"
}

# 3) NFC ECP emitter (C++) over fake RFAL/reader-storage headers (ecpfake/).
stage_nfc_ecp() {
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags -c "$HOSTD/test.c" -o "$OUT/test_harness_c.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags \
		-DCONFIG_DOOR_LOCK_RFAL_LOG_LEVEL=3 \
		-I"$HOSTD" -I"$HOSTD/ecpfake" \
		"$HOSTD/test_nfc_ecp.cpp" "$ROOT/modules/ultrawidelock_nfc/src/nfc_prop_ecp.cpp" \
		"$OUT/test_harness_c.o" \
		-o "$OUT/host_test_ecp"
	"$OUT/host_test_ecp"
}

# 4) DWM3001CDK port glue over a fake settings backend (settingsfake/).
#    Its own binary because the fake <zephyr/settings/settings.h> would collide
#    with the other suites' Zephyr surface, the same reason (1) and (3) are
#    split out. Compiled with -Wall -Wextra rather than the -w the suites above
#    use: this port has never been warning-checked by anything, since the
#    clang-format and clang-tidy gates both cover modules/ only.
#    Real port source, not a host copy -- the point is to test what ships.
stage_cdk_port() {
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -Wall -Wextra $gcc_parity $san_flags \
		-DCONFIG_LOG_DEFAULT_LEVEL=3 -DCONFIG_ULTRAWIDELOCK_PROV_CLEAR_ON_BOOT=0 \
		-I"$HOSTD" -I"$HOSTD/settingsfake" -I"$HOSTD/logfake" \
		-I"$ROOT/modules/ultrawidelock_matter/include" \
		-I"$ROOT/modules/ultrawidelock_cred/include" -I"$ROOT/ports/zephyr/store" \
		-I"$ROOT/modules/ultrawidelock_port/include" \
		"$HOSTD/test.c" "$HOSTD/test_matter_fab_settings.c" \
		"$HOSTD/test_kv_zephyr.c" \
		"$HOSTD/settingsfake/settingsfake.c" \
		"$ROOT/ports/zephyr/store/matter_fab_settings.c" \
		"$ROOT/ports/zephyr/store/kv_zephyr.c" \
		"$ROOT/ports/zephyr/store/ultrawidelock_prov_settings.c" \
		"$ROOT/modules/ultrawidelock_cred/src/ultrawidelock_prov.c" \
		-o "$OUT/host_test_cdk"
	"$OUT/host_test_cdk"
	"$ROOT/tests/ports/zephyr/matter_srp_lifecycle_check.sh"
	"$ROOT/tests/ports/zephyr/ble_link_liveness_check.sh"
}

# 5) Delta update, both halves, over the ultrawidelock_flash host backend (RAM
#    partitions that enforce the nRF driver's word and page alignment rules),
#    the host OSAL's virtual clock, the recording PSA (psafake/) and a scripted
#    detools (dfufake/). Its own binary because the SMP half needs the
#    zcbor/mcumgr doubles in smpfake/. CONFIG_MCUMGR_SMP_LEGACY_RC_BEHAVIOUR is
#    on here so the explicit "rc" key a legacy client expects is compiled and
#    checked.
#    _DEFAULT_SOURCE because dfu_receiver.c includes ultrawidelock_port.h, whose
#    ultrawidelock_uptime_us() names CLOCK_MONOTONIC. Under -std=c11 glibc hides
#    that behind a feature-test macro, so the stage does not compile on Linux at
#    all -- while Darwin exposes it unconditionally and every macOS run stays
#    green. A feature macro cannot be set from the header, because it has to
#    precede the first libc include; it belongs on the compile line, which is
#    what stage_uwb_driver above already does for the same reason.
stage_delta_update() {
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags \
		-DULTRAWIDELOCK_PORT_HOST -D_DEFAULT_SOURCE -DCONFIG_ULTRAWIDELOCK_DFU_SMP_IMG=1 -DCONFIG_ULTRAWIDELOCK_DFU_APPLIER_CHUNK=256 \
		-DCONFIG_MCUMGR_GRP_OS_RESET_HOOK=1 -DCONFIG_MCUMGR_GRP_ENUM_DETAILS_NAME=1 \
		-DCONFIG_MCUMGR_SMP_LEGACY_RC_BEHAVIOUR=1 \
		-I"$HOSTD" -I"$HOSTD/dfufake" -I"$HOSTD/smpfake" -I"$HOSTD/logfake" \
			-I"$HOSTD/psafake" -I"$ROOT/modules/ultrawidelock_port/include" \
			-I"$ROOT/modules/ultrawidelock_cred/include" \
			-I"$ROOT/modules/ultrawidelock_dfu/include" -I"$ROOT/modules/ultrawidelock_dfu/src" \
		"$HOSTD/test.c" "$HOSTD/test_dfu.c" "$HOSTD/test_dfu_smp.c" \
		"$HOSTD/dfufake/dfufake.c" "$HOSTD/smpfake/smpfake.c" "$HOSTD/psafake/psafake.c" \
		"$ROOT/tests/host/port/osal_host.c" "$ROOT/tests/host/port/flash_host.c" \
			"$ROOT/modules/ultrawidelock_dfu/src/dfu_crc.c" \
			"$ROOT/modules/ultrawidelock_dfu/src/dfu_receiver.c" \
			"$ROOT/modules/ultrawidelock_cred/src/ultrawidelock_prim_psa.c" \
			"$ROOT/modules/ultrawidelock_dfu/src/dfu_applier.c" \
		"$ROOT/ports/zephyr/dfu/dfu_smp_img.c" \
		-o "$OUT/host_test_dfu"
	"$OUT/host_test_dfu"
}

# 6) The ultrawidelock_nfc transport seam (C++), over fake Zephyr SPI/GPIO/kernel and a
#    recording credential stack (nfcfake/). pn532.c and pn532_apdu.c link in for
#    real, so the frames really are encoded and parsed by the shipping codec.
#    transport_none.cpp defines the same five symbols as transport_pn532.cpp,
#    so it is renamed on its own compile step with -DUltraWideLockNfc=UltraWideLockNfcNone -- a
#    compile flag, not a source edit, exactly as (2) renames the two crypto
#    backends.
stage_nfc_transport() {
	NFC_DEF=(-DCONFIG_ULTRAWIDELOCK_NFC_LOG_LEVEL=3 -DCONFIG_ULTRAWIDELOCK_NFC_PN532_THREAD_STACK_SIZE=2048
		-DCONFIG_ULTRAWIDELOCK_NFC_PN532_POLL_PERIOD_MS=200
		-DCONFIG_ULTRAWIDELOCK_NFC_PN532_EXCHANGE_TIMEOUT_MS=1000
		-DULTRAWIDELOCK_PORT_HOST) # transport_none logs through ultrawidelock_log.h
	NFC_INC=(-I"$HOSTD" -I"$HOSTD/nfcfake" -I"$ROOT/modules/ultrawidelock_nfc/include"
		-I"$ROOT/modules/ultrawidelock_nfc/src" -I"$ROOT/modules/ultrawidelock_port/include")
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags -c "$HOSTD/test.c" -o "$OUT/test_harness_nfc.o"
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags -I"$ROOT/modules/ultrawidelock_nfc/include" \
		-I"$ROOT/modules/ultrawidelock_nfc/src" \
		-c "$ROOT/modules/ultrawidelock_nfc/src/pn532.c" -o "$OUT/pn532_nfc.o"
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags -I"$ROOT/modules/ultrawidelock_nfc/include" \
		-I"$ROOT/modules/ultrawidelock_nfc/src" \
		-c "$ROOT/modules/ultrawidelock_nfc/src/pn532_apdu.c" -o "$OUT/pn532_apdu_nfc.o"
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags "${NFC_DEF[@]}" "${NFC_INC[@]}" \
		-c "$ROOT/ports/zephyr/nfc/pn532_bus_spi.c" -o "$OUT/pn532_bus_spi.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags "${NFC_DEF[@]}" "${NFC_INC[@]}" \
		-c "$ROOT/modules/ultrawidelock_nfc/src/transport_pn532.cpp" -o "$OUT/transport_pn532.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags -DUltraWideLockNfc=UltraWideLockNfcNone \
		"${NFC_DEF[@]}" "${NFC_INC[@]}" \
		-c "$ROOT/modules/ultrawidelock_nfc/src/transport_none.cpp" -o "$OUT/transport_none.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags "${NFC_INC[@]}" \
		-c "$HOSTD/nfcfake/nfcfake.cpp" -o "$OUT/nfcfake.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags "${NFC_DEF[@]}" "${NFC_INC[@]}" \
		-c "$HOSTD/test_nfc_transport.cpp" -o "$OUT/test_nfc_transport.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags \
		"$OUT/test_nfc_transport.o" "$OUT/nfcfake.o" "$OUT/test_harness_nfc.o" \
		"$OUT/transport_none.o" "$OUT/transport_pn532.o" "$OUT/pn532_bus_spi.o" \
		"$OUT/pn532_nfc.o" "$OUT/pn532_apdu_nfc.o" \
		-o "$OUT/host_test_nfc"
	"$OUT/host_test_nfc"
}

# 7) uwb_seam.h's engine-less tier. Compiled WITHOUT CONFIG_ULTRAWIDELOCK_CRED, alone:
#    that half of the header is inline bodies, and a header compiled two ways
#    inside one binary maps the same lines twice. See the file for the rest.
stage_uwb_seam() {
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags \
		-I"$HOSTD" -I"$HOSTD/shim" -I"$HOSTD/logfake" \
		-I"$ROOT/modules/ultrawidelock_uwb/include" -I"$SRC/driver" \
		-I"$ROOT/modules/ultrawidelock_dw3000/include" \
		"$HOSTD/test.c" "$HOSTD/test_uwb_seam.c" \
		-o "$OUT/host_test_seam"
	"$OUT/host_test_seam"
}

# 8) The credential source stack (C++): ultrawidelock_stack.cpp and session.cpp over the
#    Nordic Interface API as recording doubles (stackfake/). The protocol
#    codecs beside them are the shipping sources, linked in whole, so every
#    APDU and BLE frame here is built and parsed for real -- only the crypto
#    and the application callbacks are stand-ins. Its own binary because
#    stackfake's <ultrawidelock/*.h> are a different credential surface from the one
#    ecpfake and nfcfake carry, and all three would collide.
stage_cred_stack() {
	STK="$ROOT/modules/ultrawidelock_cred_stack/src"
	STK_DEF=(-DCONFIG_NCS_ALIRO_LOG_LEVEL_VALUE=3 -DCONFIG_NCS_ALIRO_BLE_UWB=1
		-DCONFIG_DOOR_LOCK_EXPEDITED_FAST_PHASE=1 -DCONFIG_DOOR_LOCK_STEP_UP_PHASE=1
		-DCONFIG_DOOR_LOCK_BLE_UWB_MAX_SESSIONS=2 -DCONFIG_ULTRAWIDELOCK_CRED_APDU_BUFFER_SIZE=1024
		-DCONFIG_MAX_NUMBER_OF_KPERSISTENT=4
		-DCONFIG_DOOR_LOCK_STORAGE_MAX_STORED_ACCESS_DOCUMENTS=2)
	STK_INC=(-I"$HOSTD" -I"$HOSTD/stackfake" -I"$STK" -I"$STK/protocol"
		-I"$ROOT/modules/ultrawidelock_cred/include" -I"$ROOT/modules/ultrawidelock_cred/src")
	STK_OBJS=()
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags -c "$HOSTD/test.c" -o "$OUT/test_harness_stack.o"
	for stk_src in advertising_core protocol/ble_message protocol/ble_timeout \
		protocol/nfc_select protocol/nfc_auth; do
		stk_obj="$OUT/stk_$(basename "$stk_src").o"
		# shellcheck disable=SC2086
		"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags "${STK_DEF[@]}" -I"$STK" -I"$STK/protocol" \
			-I"$ROOT/modules/ultrawidelock_cred/include" -c "$STK/$stk_src.c" -o "$stk_obj"
		STK_OBJS+=("$stk_obj")
	done
	# The step-up wire codecs + DeviceResponse parser are the shared ultrawidelock_cred
	# sources (one source of protocol truth; session.cpp calls them directly).
	for ultrawidelock_src in ultrawidelock_tlv ultrawidelock_stepup_wire ultrawidelock_stepup_parse; do
		stk_obj="$OUT/stk_$ultrawidelock_src.o"
		# shellcheck disable=SC2086
		"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags -I"$ROOT/modules/ultrawidelock_cred/include" \
			-I"$ROOT/modules/ultrawidelock_cred/src" \
			-c "$ROOT/modules/ultrawidelock_cred/src/$ultrawidelock_src.c" -o "$stk_obj"
		STK_OBJS+=("$stk_obj")
	done
	# The symmetric crypto is REAL: ultrawidelock_hash.c (SHA-256/HMAC/HKDF, pinned by
	# test_ultrawidelock_hash.c) and the reference AES-GCM in ultrawidelock_prim_host.c (pinned by
	# test_ultrawidelock_crypto.c). Only P-256 stays a stand-in -- this repo has none on host.
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags -I"$ROOT/modules/ultrawidelock_cred/include" \
		-I"$ROOT/modules/ultrawidelock_cred/src" -c "$ROOT/modules/ultrawidelock_cred/src/ultrawidelock_hash.c" \
		-o "$OUT/stk_ultrawidelock_hash.o"
	# shellcheck disable=SC2086
	"${CC:-cc}" -std=c11 -O1 -w $gcc_parity $san_flags -I"$ROOT/modules/ultrawidelock_cred/include" \
		-I"$ROOT/modules/ultrawidelock_cred/src" -c "$ROOT/tests/shared/ultrawidelock_prim_host.c" \
		-o "$OUT/stk_ultrawidelock_prim_host.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags "${STK_DEF[@]}" "${STK_INC[@]}" \
		-c "$STK/cred_stack.cpp" -o "$OUT/stk_cred_stack.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags "${STK_DEF[@]}" "${STK_INC[@]}" \
		-c "$STK/session.cpp" -o "$OUT/stk_session.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags "${STK_DEF[@]}" "${STK_INC[@]}" \
		-c "$HOSTD/stackfake/stackfake.cpp" -o "$OUT/stackfake.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags "${STK_DEF[@]}" "${STK_INC[@]}" \
		-c "$HOSTD/test_ultrawidelock_stack.cpp" -o "$OUT/test_ultrawidelock_stack.o"
	# shellcheck disable=SC2086
	"${CXX:-c++}" -std=c++17 -O1 -w $san_flags \
		"$OUT/test_ultrawidelock_stack.o" "$OUT/stackfake.o" "$OUT/test_harness_stack.o" \
		"$OUT/stk_cred_stack.o" "$OUT/stk_session.o" "${STK_OBJS[@]}" \
		"$OUT/stk_ultrawidelock_hash.o" "$OUT/stk_ultrawidelock_prim_host.o" \
		-o "$OUT/host_test_stack"
	"$OUT/host_test_stack"
}

# The core suite's build and its run were two steps; they are one now, because
# the driver below starts the stages CONCURRENTLY and these two are the only
# pair with an order between them -- the binary has to exist before it runs.
# Folding them removes the dependency instead of scheduling around it.
stage_core() {
	stage_core_build
	stage_core_run
}

# ---- running the stages concurrently ----------------------------------------
# Nine stages, each compiling its own binary from its own sources into its own
# output name, none of them reading anything another one wrote. Run one after
# another they were about seventy seconds of a single core; the machine has
# eight, and under scripts/test-runner.sh the quick suites have all finished by
# then and left it idle. So they are all started at once.
#
# THE PROGRESS DISPLAY IS UNCHANGED, deliberately. Each stage is still one
# ui_run row, in the order written below, and each row still carries that
# stage's own output and its own exit status. What changed is only WHEN the work
# happens: pl_start puts every stage in the background immediately, and the
# ui_run call for a stage waits for that stage and replays its captured output.
# So a row still cannot appear before the rows above it, the log is still in
# source order, and a failing stage still fails the suite through the same
# `set -e` path as before.
#
# The per-row times do go skewed -- the first row absorbs the wait for work that
# was already running underneath it -- which is why the total at the end is the
# number to read, not the individual rows.
_pl_dir="$(mktemp -d -t oa-host-stages.XXXXXX)"
_pl_pids=""

# The stages are compilers, and there are nine of them. If one fails, ui_run
# ends the script on the way back out and the other eight would otherwise be
# left running -- a suite that "failed" while the machine stays busy for another
# minute. Killed as a group, and the capture directory goes with them.
#
# The trap itself is installed BELOW, after ui_begin, not here: ui_attach sets
# its own EXIT/INT/TERM traps and bash keeps one handler per signal, so a trap
# set before it is silently replaced and this cleanup would never run. Same
# reason scripts/test-runner.sh sets its trap after ui_attach and calls
# _ui_cleanup from inside it.
_pl_cleanup() {
	local p
	for p in $_pl_pids; do
		kill "$p" 2>/dev/null || true
	done
	rm -rf "$_pl_dir"
}

pl_start() { # <name> <fn> -- run fn in the background, capturing output + status
	local name="$1" fn="$2"
	{
		# The stage runs in its OWN subshell, started with &, never as the
		# left side of || -- bash suppresses errexit through a condition
		# context, even an explicit `set -e` inside it, so a stage invoked
		# as `"$fn" || rc=$?` keeps going after a failed compile and RUNS
		# THE PREVIOUS BINARY. That reported a green suite over code that
		# did not build. Here -e is live inside the stage: the first
		# failing compiler ends it, and wait carries out its real status.
		(set -e; "$fn") >"$_pl_dir/$name.out" 2>&1 &
		local inner=$!
		local rc=0
		wait "$inner" || rc=$?
		printf '%s' "$rc" >"$_pl_dir/$name.rc"
	} &
	_pl_pids="$_pl_pids $!"
	eval "_pl_pid_$name=$!"
}

pl_wait() { # <name> -- block for that stage, print its output, return its status
	local name="$1" pid rc
	eval "pid=\$_pl_pid_$name"
	# `wait` first, because it is free and exact when it applies. It does not
	# always apply: ui_run's fancy mode runs its command in a subshell to poll
	# the capture file, and a subshell cannot wait on its parent's job -- it
	# returns "not a child of this shell" immediately, which would have pl_wait
	# read a status file the stage has not written yet and call a passing stage
	# a failure. So the status file is what is actually waited on. pl_start
	# writes it last, after the output file is closed, so its appearance means
	# the whole stage is on disk.
	wait "$pid" 2>/dev/null || true
	while [ ! -s "$_pl_dir/$name.rc" ]; do
		sleep 0.05 2>/dev/null || sleep 1
	done
	cat "$_pl_dir/$name.out" 2>/dev/null || true
	rc="$(cat "$_pl_dir/$name.rc")"
	return "$rc"
}

pl_start core stage_core
pl_start uwb_driver stage_uwb_driver
pl_start crypto stage_crypto_backends
pl_start nfc_ecp stage_nfc_ecp
pl_start cdk_port stage_cdk_port
pl_start delta stage_delta_update
pl_start nfc_transport stage_nfc_transport
pl_start uwb_seam stage_uwb_seam
pl_start cred_stack stage_cred_stack

# The ":seconds" are first-run hints only, measured on the machine this was
# written on. From the second run the real durations come out of the cache under
# build/_ui, so the percentage is this checkout's own timings, not these. The
# sanitized build is several times slower and gets its own cache.
ULTRAWIDELOCK_UI_KEY="host-run${SAN:+-san}"
ui_begin "host test suite${SAN:+ (ASan + UBSan)}" \
	"core suite:6" "uwb driver + shell:1" \
	"crypto backends:1" "nfc ecp emitter:1" "cdk port glue:1" \
	"delta update + smp:1" "nfc transport:1" "uwb seam tier:1" \
	"credential stack:2"

# After ui_begin, so these replace ui.sh's handlers rather than being replaced
# by them, and each one still does ui.sh's own cleanup before ending.
trap '_pl_cleanup; _ui_cleanup' EXIT
trap '_pl_cleanup; _ui_cleanup; trap - INT; kill -INT $$' INT
trap '_pl_cleanup; _ui_cleanup; trap - TERM; kill -TERM $$' TERM

ui_run "core suite" pl_wait core
ui_run "uwb driver + shell" pl_wait uwb_driver
ui_run "crypto backends" pl_wait crypto
ui_run "nfc ecp emitter" pl_wait nfc_ecp
ui_run "cdk port glue" pl_wait cdk_port
ui_run "delta update + smp" pl_wait delta
ui_run "nfc transport" pl_wait nfc_transport
ui_run "uwb seam tier" pl_wait uwb_seam
ui_run "credential stack" pl_wait cred_stack
ui_end
