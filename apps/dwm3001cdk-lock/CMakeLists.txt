# DWM3001CDK standalone credential lock: the reader engine, the CCC/FiRa responder,
# the DW3110 driver and the BLE stack in one nRF52833 image.
#
# ultrawidelock_uwb and modules/ultrawidelock_dw3000 come in as Zephyr modules because they carry their own
# Kconfig gating. modules/ultrawidelock_cred's reader core is listed
# directly here, the way tests/on_target/zephyr/nrf5340dk-ultrawidelock-device-ec does, so the nRF5340 build
# that consumes that module through CONFIG_ULTRAWIDELOCK_CRED_STACK stays untouched.
cmake_minimum_required(VERSION 3.20.0)

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
# modules/ultrawidelock_cred supplies this app's Kconfig and its named primitive
# provider. The reader sources remain listed directly below; keeping
# CONFIG_ULTRAWIDELOCK_CRED_STACK=n prevents the credential library from being
# compiled a second time.
# modules/ultrawidelock_anchor is listed on the same terms: its CMakeLists is gated on
# CONFIG_ULTRAWIDELOCK_ANCHOR, which is default n, so listing it here costs the default
# build nothing and only makes `overlay-anchor.conf` able to turn it on.
# modules/ultrawidelock_ml likewise, gated on CONFIG_ULTRAWIDELOCK_ML_LOS: default n, so the shipping
# image is byte-identical without it and only overlays/mlgate.conf turns it on.
list(APPEND ZEPHYR_EXTRA_MODULES
	"${REPO_ROOT}/modules/ultrawidelock_cred"
	"${REPO_ROOT}/modules/ultrawidelock_anchor"
	"${REPO_ROOT}/modules/ultrawidelock_matter"
	"${REPO_ROOT}/modules/ultrawidelock_ml"
	"${REPO_ROOT}/modules/ultrawidelock_uwb"
	"${REPO_ROOT}/modules/ultrawidelock_dw3000"
	"${REPO_ROOT}/ports/zephyr")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ultrawidelock_reader_dwm3001cdk)

# Faster UWB evidence settings are measurements, not release policy. Refuse a
# configuration that could lower either floor without both explicit bench
# acknowledgement and strict STS enforcement.
if((CONFIG_ULTRAWIDELOCK_RANGE_TRUST_K LESS 3 OR
    CONFIG_ULTRAWIDELOCK_APPROACH_NEAR_DWELL LESS 2) AND
   (NOT CONFIG_ULTRAWIDELOCK_BENCH OR NOT CONFIG_ULTRAWIDELOCK_RANGE_GATE_STRICT))
	message(FATAL_ERROR
		"Reduced UWB consensus/dwell requires CONFIG_ULTRAWIDELOCK_BENCH=y "
		"and CONFIG_ULTRAWIDELOCK_RANGE_GATE_STRICT=y")
endif()

# APPROTECT must never be locked on this board. SystemInit() re-asserts the lock
# on every boot and the only way out is `nrfjprog --recover`, which mass-erases
# flash AND UICR -- taking settings_storage at 0x7c000 with it, and with that the
# reader private key and every iPhone key already provisioned against this board.
#
# This is the configure-time half of the guard: it fails the build of THIS image
# before a hex exists. scripts/check-approtect.sh is the other half and is the
# one that covers MCUboot, whose config lives outside this CMakeLists entirely.
# Both are needed -- the setting can arrive from a board defconfig or an SoC
# default that no grep of this tree would find, which is why the check that
# matters reads the GENERATED .config.
if(CONFIG_NRF_APPROTECT_LOCK OR CONFIG_NRF_SECURE_APPROTECT_LOCK)
	message(FATAL_ERROR
		"APPROTECT lock is enabled for this image. Refusing to build.\n"
		"  CONFIG_NRF_APPROTECT_LOCK        = ${CONFIG_NRF_APPROTECT_LOCK}\n"
		"  CONFIG_NRF_SECURE_APPROTECT_LOCK = ${CONFIG_NRF_SECURE_APPROTECT_LOCK}\n"
		"Locking is a one-way door for this board's DATA: recovering debug "
		"access costs a mass erase of flash and UICR, which destroys "
		"settings_storage and the reader identity. Export it first with "
		"`ultrawidelock export yes` if you genuinely intend this.")
endif()

set(CRED "${REPO_ROOT}/modules/ultrawidelock_cred")
set(PORTZ "${REPO_ROOT}/ports/zephyr")

# Reader-role source sets come from the role manifests (modules/ultrawidelock_cred/
# roles/*.list) — the same lists the ESP32 components, the nRF5340 apps and the
# host suite read, so each role's file set exists in exactly one place. The
# crypto role is composition only; this image's PSA implementation is the
# named ultrawidelock_prim library contributed by the credential module.
include("${REPO_ROOT}/cmake/ultrawidelock_roles.cmake")
ultrawidelock_role_sources("${CRED}/roles/reader.list" ULTRAWIDELOCK_READER_SRCS)
ultrawidelock_role_sources("${CRED}/roles/reader_policy.list" ULTRAWIDELOCK_POLICY_SRCS)
ultrawidelock_role_sources("${CRED}/roles/apdu.list" ULTRAWIDELOCK_APDU_SRCS)
ultrawidelock_role_sources("${CRED}/roles/crypto.list" ULTRAWIDELOCK_CRYPTO_SRCS)
ultrawidelock_role_sources("${CRED}/roles/hash.list" ULTRAWIDELOCK_HASH_SRCS)
ultrawidelock_role_sources("${CRED}/roles/dyntag.list" ULTRAWIDELOCK_DYNTAG_SRCS)
ultrawidelock_role_sources("${CRED}/roles/ble_central.list" ULTRAWIDELOCK_BLE_CENTRAL_SRCS)

target_sources(app PRIVATE
	src/main.c
	src/ml_feed.c
	# Platform seams the reader engine links against, re-homed to ports/zephyr
	# with the rest of the Zephyr glue. Listed by path rather than compiled by
	# the ultrawidelock_zephyr_port module because they are unconditional app glue with
	# no Kconfig gate to ride — this app IS the gate.
	${PORTZ}/ble/ultrawidelock_ble_zephyr.c
	${PORTZ}/store/ultrawidelock_prov_settings.c
	# Reader engine: roles reader + reader_policy + apdu + crypto + hash + dyntag.
	${ULTRAWIDELOCK_READER_SRCS}
	${ULTRAWIDELOCK_POLICY_SRCS}
	${ULTRAWIDELOCK_APDU_SRCS}
	${ULTRAWIDELOCK_CRYPTO_SRCS}
	${ULTRAWIDELOCK_HASH_SRCS}
	${ULTRAWIDELOCK_DYNTAG_SRCS}
)
target_link_libraries(app PRIVATE ultrawidelock_prim)
if(CONFIG_ULTRAWIDELOCK_CRED_STEPUP)
	# The step-up (Access Document) phase: the verifier plus the wire codecs
	# role (DeviceResponse parser, SessionData/ENVELOPE codecs). Compiled the
	# way the ESP32 reader component compiles them; ultrawidelock_stepup.c is
	# allowlisted as NOT_MANIFESTED in tests/tooling/port_purity_check.sh.
	ultrawidelock_role_sources("${CRED}/roles/wire_codecs.list" ULTRAWIDELOCK_WIRE_CODEC_SRCS)
	target_sources(app PRIVATE
		"${CRED}/src/ultrawidelock_stepup.c"
		${ULTRAWIDELOCK_WIRE_CODEC_SRCS}
	)
	# This part is out of both RAM and flash (nRF52833: 128 KiB / 423.5 KiB app
	# slot, 98% of each before step-up). The parsed document is static RAM: an
	# Access Document carries a handful of elements (the spec example has 3
	# digests and 1 item), so 12 and 8 keep the struct near 1.3 KiB instead of
	# 2.2. LEAN drops what this reader never reads from the document -- the
	# dates (no trusted clock), the COSE alg label and the x5chain (only a
	# provisioned issuer may vouch) -- for about 0.6 KiB of flash.
	target_compile_definitions(app PRIVATE
		ULTRAWIDELOCK_STEPUP_MAX_DIGESTS=12u
		ULTRAWIDELOCK_STEPUP_MAX_ITEMS=8u
		ULTRAWIDELOCK_STEPUP_LEAN=1
	)
endif()
if(CONFIG_ULTRAWIDELOCK_BENCH_CRED_O2)
	set_source_files_properties(
		"${CRED}/src/ultrawidelock_reader.c"
		"${CRED}/src/ultrawidelock_crypto.c"
		"${CRED}/src/ultrawidelock_hash.c"
		PROPERTIES COMPILE_OPTIONS "-O2")
	target_compile_options(ultrawidelock_prim PRIVATE -O2)
endif()
# Provisioning console (USB CDC-ACM, provisioning mode only). Dropped by
# 4bdfd44a, which replaced this line with the side_feed one below instead of
# adding it, and so deleted `ultrawidelock import/export/erase` from every build
# without deleting the file or the comment. Restored, and the two lines are kept
# apart so the next edit here cannot repeat it.
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_PROV_CONSOLE app PRIVATE src/prov_shell.c)

# Bench commands typed at the RTT terminal (`trust`, `prov`): the only input
# this image has, since the USB console above is off in the Matter build.
target_sources(app PRIVATE src/rtt_bench.c)

# The side gate's bench feed: an RTT buffer drained by host tooling.
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_SIDE_GATE app PRIVATE src/side_feed.c)
# The deployed witness transport. Separate from SIDE_GATE's bench feed: this
# one binds a Thread socket instead of draining an RTT buffer, so it is gated
# on its own symbol and the RTT path stays available for bench work.
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_SEALED_LINK app PRIVATE src/witness_link.c)
# Measurement only; CONFIG_ULTRAWIDELOCK_THREAD_GATE defaults n so this is absent from
# every shipping image.
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_THREAD_GATE app PRIVATE src/thread_gate.c)
# The two DoorLockAlarms, and the door-angle state they need. ANCHOR is default
# n, so the shipping image never compiles this. Both symbols, not just ANCHOR:
# the alarm is a Matter event, and `make reader ANCHOR=1` is an anchor build
# with no Matter node to carry one.
if(CONFIG_ULTRAWIDELOCK_ANCHOR AND CONFIG_ULTRAWIDELOCK_MATTER_BLE)
	target_sources(app PRIVATE src/door_alarm.c)
endif()
# The DFU receiver's BLE transport (ports/zephyr/dfu/dfu_ble_zephyr.c) and the
# rest of the gated Zephyr glue compile via the ultrawidelock_zephyr_port module under
# the same CONFIG symbols.
# The board's only output. NOT gated on the DFU receiver any more: the update
# window was the first thing worth showing, not the only one, and the `reader`
# image has no receiver and used to light nothing at all.
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_STATUS_LED app PRIVATE src/status_led.c)
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_CIRDIAG_CAPTURE app PRIVATE src/cirdiag_capture.c)
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_CASE_BENCH app PRIVATE src/case_bench.c)
# Initiator (User-Device role) transport: ultrawidelock_zephyr_port compiles the central
# mirror of ultrawidelock_ble_zephyr.c under this gate; the platform-free advert/READ
# decoder it calls is the same translation unit the ESP32 port and the host
# suite compile.
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_BLE_CENTRAL app PRIVATE ${ULTRAWIDELOCK_BLE_CENTRAL_SRCS})
# The commissioning policy half; its transport, Thread/fabric ports and fabric
# table store live in ports/zephyr/{matter,store} under the same gate.
target_sources_ifdef(CONFIG_ULTRAWIDELOCK_MATTER_BLE app PRIVATE
	src/matter_commission.c
	src/uwb_matter_presence.c)
# The client role: what turns the four protocol files in ultrawidelock_matter
# into a lock that unlocks another lock. Both symbols, not just the client one,
# for the same reason door_alarm.c needs both above: the routing hooks it
# depends on live in matter_commission.c.
if(CONFIG_ULTRAWIDELOCK_MATTER_CLIENT AND CONFIG_ULTRAWIDELOCK_MATTER_BLE)
	target_sources(app PRIVATE src/matter_client.c)
endif()

# CONFIG_MBEDTLS_MEMORY_DEBUG=y is a NO-OP in this build and sets no define.
# nrf_security only wires that symbol through configs/legacy_crypto_config.h.template
# (`#cmakedefine MBEDTLS_MEMORY_DEBUG`, line 1268); a PSA-only build
# (CONFIG_OBERON_ONLY_PSA_ENABLED) generates nrf-config.h from a different
# template that has no slot for it, so the Kconfig is accepted and silently
# dropped. The app then compiles against a declaration the library never
# defined and the link fails on mbedtls_memory_buffer_alloc_max_get.
#
# Define it for every target instead. Safe because the only struct it changes,
# buffer_alloc_ctx, is file-local to mbedtls/library/memory_buffer_alloc.c, so
# there is no layout to get out of step across compilation units.
if(CONFIG_ULTRAWIDELOCK_HEAP_PROBE)
	zephyr_compile_definitions(MBEDTLS_MEMORY_DEBUG)
endif()
# src for matter_commission.h (included by the re-homed ultrawidelock_ble_zephyr.c);
# ${PORTZ}/{matter,store} for the re-homed matter_ble_zephyr.h and
# matter_fab_settings.h, which main.c and matter_commission.c include
# regardless of CONFIG_ULTRAWIDELOCK_MATTER_BLE.
target_include_directories(app PRIVATE ${CRED}/include ${CRED}/src src
	${PORTZ}/matter ${PORTZ}/store)
