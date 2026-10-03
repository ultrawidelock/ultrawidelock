# UltraWideLock UWB (credential DS-TWR responder) engine as an ESP-IDF component.
# Additive: reuses modules/ultrawidelock_uwb/src + modules/ultrawidelock_dw3000 from the repo unchanged.
# The engine is platform-neutral: it takes its OS surface from ultrawidelock_port.h and
# its logging from ultrawidelock_log.h (modules/ultrawidelock_port/include), which select the ESP-IDF
# backend on ESP_PLATFORM. No Zephyr compat layer is involved. The DW3000
# platform SPI/GPIO layer is the ESP-IDF backend in port/.
# Source set = the role manifests in modules/{ultrawidelock_uwb,ultrawidelock_dw3000}/roles/ — the
# SAME lists modules/ultrawidelock_uwb/CMakeLists.txt reads for CONFIG_ULTRAWIDELOCK_UWB +
# RESPONDER + CRED (no PRETTY/SHELL/SELFTEST, no uwb_rxdiag:
# those stay Zephyr-module literals) — plus the port/*.c locals below.

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
set(UWB_SRC "${REPO_ROOT}/modules/ultrawidelock_uwb/src")
set(ULTRAWIDELOCK_INC "${REPO_ROOT}/modules/ultrawidelock_uwb/include")
set(ULTRAWIDELOCK_PORT "${REPO_ROOT}/modules/ultrawidelock_port/include")
set(ULTRAWIDELOCK_CRED "${REPO_ROOT}/modules/ultrawidelock_cred/include")
set(DW  "${REPO_ROOT}/modules/ultrawidelock_dw3000")
set(UWBROLES "${REPO_ROOT}/modules/ultrawidelock_uwb/roles")
set(DWROLES "${REPO_ROOT}/modules/ultrawidelock_dw3000/roles")

include("${REPO_ROOT}/cmake/ultrawidelock_roles.cmake")
# engine: driver + fira (ds_twr = shared ToF estimator; ccc_shim_rx.c calls it)
ultrawidelock_role_sources("${UWBROLES}/base_driver.list" UWB_BASE_DRIVER_SRCS)
ultrawidelock_role_sources("${UWBROLES}/base_engine.list" UWB_BASE_ENGINE_SRCS)
ultrawidelock_role_sources("${UWBROLES}/responder_driver.list" UWB_RESP_DRIVER_SRCS)
ultrawidelock_role_sources("${UWBROLES}/responder_engine.list" UWB_RESP_ENGINE_SRCS)
# engine: CCC STS + thin AES-ECB adapter over ultrawidelock_prim
ultrawidelock_role_sources("${UWBROLES}/ccc_keys.list" UWB_CCC_KEYS_SRCS)
ultrawidelock_role_sources("${UWBROLES}/ccc_engine.list" UWB_CCC_ENGINE_SRCS)
ultrawidelock_role_sources("${UWBROLES}/crypto_prim.list" UWB_CRYPTO_SRCS)
# engine: credential ranging-setup adapter + M1-M4 codec
ultrawidelock_role_sources("${UWBROLES}/ultrawidelock_adapter.list" UWB_ULTRAWIDELOCK_ADAPTER_SRCS)
ultrawidelock_role_sources("${UWBROLES}/ultrawidelock_codec.list" UWB_ULTRAWIDELOCK_CODEC_SRCS)
# vendor decadriver (modules/ultrawidelock_dw3000/roles/ canonical set)
ultrawidelock_role_sources("${DWROLES}/core.list" DW_CORE_SRCS)
ultrawidelock_role_sources("${DWROLES}/chip_dw3000.list" DW_CHIP_SRCS)

set(ULTRAWIDELOCK_SRCS
    ${UWB_BASE_DRIVER_SRCS}
    ${UWB_BASE_ENGINE_SRCS}
    ${UWB_RESP_DRIVER_SRCS}
    ${UWB_RESP_ENGINE_SRCS}
    ${UWB_CCC_KEYS_SRCS}
    ${UWB_CCC_ENGINE_SRCS}
    ${UWB_CRYPTO_SRCS}
    ${UWB_ULTRAWIDELOCK_ADAPTER_SRCS}
    ${UWB_ULTRAWIDELOCK_CODEC_SRCS}
    ${DW_CORE_SRCS}
    ${DW_CHIP_SRCS}
    # ESP-IDF platform backend (replaces Zephyr dw3000_spi.c / dw3000_hw.c)
    "port/dw3000_spi.c"
    "port/dw3000_hw.c"
    "port/ultrawidelock_seam_stubs.c"
)

# CIA/CIR diagnostics: per-reception first-path summary + windowed CIR tap dump
# (gated, default n; the RX-shim call sites no-op when unset).
if(CONFIG_ULTRAWIDELOCK_UWB_CIRDIAG)
    ultrawidelock_role_sources("${UWBROLES}/diag_cir.list" UWB_DIAG_CIR_SRCS)
    list(APPEND ULTRAWIDELOCK_SRCS ${UWB_DIAG_CIR_SRCS})
endif()

# Flight recorder: record a live walk-up into a RAM ring for host replay
# (gated, default n; the ccc_shim_rx.c call sites no-op when unset).
if(CONFIG_ULTRAWIDELOCK_FLIGHT_RECORDER)
    ultrawidelock_role_sources("${UWBROLES}/flight_recorder.list" UWB_FLIGHT_SRCS)
    list(APPEND ULTRAWIDELOCK_SRCS ${UWB_FLIGHT_SRCS})
endif()

idf_component_register(
    SRCS ${ULTRAWIDELOCK_SRCS}
    INCLUDE_DIRS
        "${ULTRAWIDELOCK_PORT}"          # ultrawidelock_port.h / ultrawidelock_log.h — the platform contract
        "${ULTRAWIDELOCK_INC}"           # facade, seams, diagnostics and ranging-setup API
    PRIV_INCLUDE_DIRS
        "port"                 # board_pins.h
        "${UWB_SRC}/driver" "${UWB_SRC}/fira" "${UWB_SRC}/ccc" "${UWB_SRC}/facade"
		"${UWB_SRC}/cred"
		"${ULTRAWIDELOCK_CRED}"
		"${DW}/include"
        "${DW}/dwt_uwb_driver"
        "${DW}/dwt_uwb_driver/lib/qmath/include"
    REQUIRES
        # ultrawidelock_port carries the ESP-IDF backend of the contract this engine is
        # written against. Named here rather than left to the ULTRAWIDELOCK_PORT include
        # path above: ESP-IDF only builds a component something requires, so
        # without this the backend is discovered and then silently skipped.
        ultrawidelock_port
        driver esp_timer ultrawidelock_crypto
)

# The engine + vendor decadriver were written for the Nordic/Zephyr warning
# regime (e.g. int32_t == int, so %d matched). ESP-IDF defaults to -Werror=all,
# which flags benign format/maybe-uninitialized diffs in this reused code. Keep
# warnings visible but non-fatal for this component only (don't edit shared or
# vendor source). Our own port/ files still get reviewed against these warnings.
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-error -Wno-format -Wno-maybe-uninitialized)

# Kconfig symbols the in-tree build gates on, supplied as compile defs.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    CONFIG_ULTRAWIDELOCK_UWB=1
    CONFIG_ULTRAWIDELOCK_UWB_RESPONDER=1
    CONFIG_ULTRAWIDELOCK_CRED=1
    CONFIG_DW3000=1
    CONFIG_DW3000_CHIP_DW3000=1
    # The CDK's Final_Data path: a delayed SP0 RX window scheduled in hardware
    # at the Final_Data slot, the deferred Pre-POLL decode moved after that arm,
    # and the post-FINAL fate counters. Its Kconfig help already says ESP32 uses
    # it, but only the timestamp snapshot was ever keyed on ESP_PLATFORM; the
    # window was not, so the FINAL callback re-armed SP0 by hand and the SP0
    # Final_Data 2 ms behind the FINAL was never decoded (field log, ESP32-S3:
    # 45 Responses sent, final=0 range=0; FINAL itself caught with cper=0).
    # The port already defines the g_dw_cyc_* stamps this consumes.
    CONFIG_ULTRAWIDELOCK_UWB_FINAL_SNAPSHOT=1
)

# Two-anchor rounds. A project sets these before including project.cmake, so
# ONE engine serves the lock (responder 0 of 1, the validated baseline) and the
# satellite (responder 1 of 2, transmitting Response_1 at POLL+2 slots).
# See modules/ultrawidelock_uwb/src/ccc/cred_round_config.h: the count appears
# in the M3 attribute and in rcfg[12] and MUST agree, or every derived STS
# diverges and nothing decodes.
#
# The CMake variable wins because it is the explicit, per-project statement
# (the satellite pins 2/1 this way). When it is absent, the component's
# Kconfig supplies the value: its defaults are the header's own 1 and 0, so an
# app whose sdkconfig says nothing still gets the definitions it got before
# either mechanism existed — the reader image cannot move because of it.
if(DEFINED ULTRAWIDELOCK_NUM_RESPONDERS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        CONFIG_ULTRAWIDELOCK_NUM_RESPONDERS=${ULTRAWIDELOCK_NUM_RESPONDERS})
elseif(DEFINED CONFIG_ULTRAWIDELOCK_NUM_RESPONDERS)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        CONFIG_ULTRAWIDELOCK_NUM_RESPONDERS=${CONFIG_ULTRAWIDELOCK_NUM_RESPONDERS})
endif()
if(DEFINED ULTRAWIDELOCK_RESPONDER_INDEX)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        CONFIG_ULTRAWIDELOCK_RESPONDER_INDEX=${ULTRAWIDELOCK_RESPONDER_INDEX})
elseif(DEFINED CONFIG_ULTRAWIDELOCK_RESPONDER_INDEX)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        CONFIG_ULTRAWIDELOCK_RESPONDER_INDEX=${CONFIG_ULTRAWIDELOCK_RESPONDER_INDEX})
endif()

# The CCC STS seam is modules/ultrawidelock_uwb/include/uwb_seam.h: every caller reaches
# the radio through ultrawidelock_uwb_arm_rx / _set_sts_iv / _set_callbacks / _configure_phy,
# so there is no link-time interposition to declare here. ccc_shim_rx.c and
# ccc_shim_wrap.c supply the first two; port/ultrawidelock_seam_stubs.c supplies the last
# two, standing in for the uwb_rxdiag.c this port omits (a diagnostic, not a
# dependency: it is portable since T2a, and nothing on this port reads it).
