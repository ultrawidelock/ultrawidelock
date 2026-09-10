#!/usr/bin/env bash
#
# Host tests for ESP-owned glue, followed by the target build and link guard.
#
# On-target functional tests (Unity on the DW3000 SPI/IRQ path) are deferred:
# they need the DWM3000EVB wired up.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
SHARED="$HERE/../../../tests/shared"
CRED="$HERE/../../../modules/ultrawidelock_cred"
ULTRAWIDELOCK_PORT_INC="$HERE/../../../modules/ultrawidelock_port/include"
UWB_INC="$HERE/../../../modules/ultrawidelock_uwb/include"
ESP_COMPONENTS="$REPO_ROOT/ports/esp32/components"
READER_MAIN="$REPO_ROOT/examples/esp32/reader/main"

echo "== host: bolt-state LED policy =="
MATTER_MAIN="$REPO_ROOT/apps/esp32-matter-lock/main"
LBIN="$(mktemp -t lock_led.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra \
   -I "$MATTER_MAIN" \
   "$HERE/test_lock_led.c" "$MATTER_MAIN/lock_led.c" -o "$LBIN"
"$LBIN"
rm -f "$LBIN"

echo
echo "== host: ultrawidelock_ble transport vs NimBLE fakes =="
# Target-only sources compiled against the recording doubles in sdkfake/.
# These suites prove branch logic + wiring against the fakes, not hardware
# truth; the dynamic-tag advert bytes are cross-checked against
# ultrawidelock_advtag_derive. See sdkfake/sdkfake.h.
# Two files because bring-up is split: ultrawidelock_ble_nimble.c is the shared NimBLE
# backend (also built by the standalone FreeRTOS port) and ultrawidelock_ble_esp32.c is
# the ESP-IDF half. ESP_PLATFORM selects ultrawidelock_log.h's ESP branch, which resolves
# to sdkfake's esp_log.h -- the same path the target takes.
SDKFAKE="$HERE/sdkfake"
EBIN="$(mktemp -t esp_ultrawidelock_ble.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra \
   -I "$SDKFAKE" -I "$CRED/include" -I "$CRED/src" -I "$ULTRAWIDELOCK_PORT_INC" \
   -DESP_PLATFORM \
   "$HERE/test_esp_ultrawidelock_ble.c" \
   "$ESP_COMPONENTS/ultrawidelock_ble/ultrawidelock_ble_esp32.c" \
   "$CRED/src/ultrawidelock_ble_nimble.c" \
   "$CRED/src/ultrawidelock_advtag.c" "$CRED/src/ultrawidelock_hash.c" \
   "$SHARED/ultrawidelock_prim_host.c" \
   "$SDKFAKE/fake_nimble.c" "$SDKFAKE/fake_nvs.c" -o "$EBIN"
"$EBIN"
rm -f "$EBIN"

echo
echo "== host: DFU GATT service vs NimBLE fakes =="
# dfu_ble_esp32.c compiled unmodified; the receiver is stubbed in the test.
# Guards the listener-registration ORDER the target cannot check for itself.
DFUBIN="$(mktemp -t esp_dfu_ble.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra \
   -I "$SDKFAKE" -I "$ESP_COMPONENTS/ultrawidelock_dfu/include" \
   -I "$REPO_ROOT/modules/ultrawidelock_dfu/include" \
   "$HERE/test_esp_dfu_ble.c" \
   "$ESP_COMPONENTS/ultrawidelock_dfu/dfu_ble_esp32.c" \
   "$SDKFAKE/fake_nimble.c" -o "$DFUBIN"
"$DFUBIN"
rm -f "$DFUBIN"

echo
echo "== host: ultrawidelock_prov NVS backend vs in-RAM NVS fake =="
NBIN="$(mktemp -t esp_prov_nvs.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra \
   -I "$SDKFAKE" -I "$CRED/include" -I "$REPO_ROOT/modules/ultrawidelock_port/include" \
   "$HERE/test_esp_prov_nvs.c" \
   "$ESP_COMPONENTS/ultrawidelock_reader/ultrawidelock_prov_nvs.c" \
   "$ESP_COMPONENTS/ultrawidelock_port/kv_nvs.c" \
   "$CRED/src/ultrawidelock_prov.c" \
   "$SDKFAKE/fake_nvs.c" -o "$NBIN"
"$NBIN"
rm -f "$NBIN"

echo
echo "== host: ultrawidelock_kv NVS backend vs in-RAM NVS fake =="
KBIN="$(mktemp -t esp_kv_nvs.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra \
   -I "$SDKFAKE" -I "$REPO_ROOT/modules/ultrawidelock_port/include" \
   "$HERE/test_esp_kv_nvs.c" \
   "$ESP_COMPONENTS/ultrawidelock_port/kv_nvs.c" \
   "$SDKFAKE/fake_nvs.c" -o "$KBIN"
"$KBIN"
rm -f "$KBIN"

echo
echo "== host: ultrawidelock_stepup worker vs FreeRTOS fakes =="
# The queue/task doubles are pumped synchronously; the decrypt/parse/verify
# underneath is the real shared-core code on the stepup_vectors.h KATs.
WBIN="$(mktemp -t esp_stepup_worker.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra -DCONFIG_ULTRAWIDELOCK_CRED_STEPUP=1 \
   -I "$SDKFAKE" -I "$HERE" -I "$SHARED" -I "$CRED/include" -I "$CRED/src" \
   "$HERE/test_esp_stepup_worker.c" \
   "$ESP_COMPONENTS/ultrawidelock_reader/ultrawidelock_stepup_worker.c" \
   "$CRED/src/ultrawidelock_stepup.c" "$CRED/src/ultrawidelock_stepup_wire.c" \
   "$CRED/src/ultrawidelock_stepup_parse.c" "$CRED/src/ultrawidelock_tlv.c" \
   "$CRED/src/ultrawidelock_hash.c" "$CRED/src/ultrawidelock_crypto.c" \
   "$SHARED/ultrawidelock_prim_host.c" \
   "$SDKFAKE/fake_freertos.c" -o "$WBIN"
"$WBIN"
rm -f "$WBIN"

echo
echo "== host: demand-driven presence proof freshness =="
# The command loop is real. Reader/UWB doubles expose the epoch boundaries, and
# the real assertion codec proves stale auth/range, wrong credential, far range,
# reset timeout and ambiguous trust all fail before the signer is called.
PLBIN="$(mktemp -t esp_presence_link.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra \
   -D_POSIX_C_SOURCE=200809L -DULTRAWIDELOCK_PORT_HOST \
   -DCONFIG_ULTRAWIDELOCK_PRESENCE_TIMEOUT_MS=1 -DCONFIG_ULTRAWIDELOCK_PRESENCE_MAX_CM=40 \
   -I "$SDKFAKE" -I "$ESP_COMPONENTS/ultrawidelock_reader" \
   -I "$CRED/include" -I "$CRED/src" -I "$ULTRAWIDELOCK_PORT_INC" \
   -I "$UWB_INC" \
   "$HERE/test_esp_presence_link.c" \
   "$ESP_COMPONENTS/ultrawidelock_reader/presence_link.c" \
   "$CRED/src/ultrawidelock_assert.c" "$CRED/src/ultrawidelock_hash.c" \
   "$SDKFAKE/fake_nvs.c" -o "$PLBIN"
"$PLBIN" | grep -E '^(--|  ok|  FAIL|RESULT)'
rm -f "$PLBIN"

echo
echo "== host: PIV CCID protocol core =="
PIVBIN="$(mktemp -t esp_piv_ccid.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra -Werror \
   -I "$ESP_COMPONENTS/piv_ccid/include" \
   "$HERE/test_piv_ccid.c" \
   "$ESP_COMPONENTS/piv_ccid/piv_ccid.c" \
   "$ESP_COMPONENTS/piv_ccid/piv_apdu.c" -o "$PIVBIN"
"$PIVBIN"
rm -f "$PIVBIN"

echo
echo "== host: reader bench console vs esp_console fakes =="
CSBIN="$(mktemp -t esp_app_shell.XXXXXX)"
# _POSIX_C_SOURCE because main.c now includes ultrawidelock_port.h, whose host build calls
# clock_gettime(CLOCK_MONOTONIC): glibc declares neither without it, while macOS
# declares both unconditionally, so omitting it builds locally and fails on CI.
cc -std=c11 -O1 -Wall -Wextra -D_POSIX_C_SOURCE=200809L \
   -DCONFIG_ULTRAWIDELOCK_CRED_STEPUP=1 -DULTRAWIDELOCK_PORT_HOST \
	-I "$SDKFAKE" -I "$READER_MAIN" \
   -I "$UWB_INC" \
   -I "$CRED/include" -I "$ULTRAWIDELOCK_PORT_INC" \
   "$HERE/test_esp_app_shell.c" \
   "$READER_MAIN/app_shell.c" \
   "$READER_MAIN/main.c" \
   "$SDKFAKE/fake_freertos.c" "$SDKFAKE/fake_esp.c" -o "$CSBIN"
# pipefail keeps the binary's exit status; the grep hides the handlers' own
# bench printf noise without dropping any ok/FAIL/RESULT line.
"$CSBIN" | grep -E '^(--|  ok|  FAIL|RESULT)'
rm -f "$CSBIN"

echo
echo "== host: DW3000 ESP-IDF backend vs GPIO/SPI fakes (S3 dual-core) =="
DBIN="$(mktemp -t esp_dw3000_port.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra -DCONFIG_ULTRAWIDELOCK_UWB_CIRDIAG=1 -DCONFIG_ULTRAWIDELOCK_CRED=1 \
   -DCONFIG_IDF_TARGET_ESP32S3=1 \
   -DCONFIG_FREERTOS_NUMBER_OF_CORES=2 \
   -DCONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=240 \
   -I "$SDKFAKE" -I "$ESP_COMPONENTS/ultrawidelock_uwb/port" \
   -I "$UWB_INC" \
   -I "$HERE/../../../modules/ultrawidelock_dw3000/include" \
   -I "$HERE/../../../modules/ultrawidelock_dw3000/dwt_uwb_driver" \
   "$HERE/test_esp_dw3000_port.c" \
   "$ESP_COMPONENTS/ultrawidelock_uwb/port/dw3000_hw.c" \
   "$ESP_COMPONENTS/ultrawidelock_uwb/port/dw3000_spi.c" \
   "$SDKFAKE/fake_driver.c" "$SDKFAKE/fake_freertos.c" -o "$DBIN"
"$DBIN"
rm -f "$DBIN"

echo
echo "== host: DW3000 ESP-IDF backend vs GPIO/SPI fakes (C6 single-core) =="
DBIN="$(mktemp -t esp_dw3000_port_c6.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra -DCONFIG_ULTRAWIDELOCK_UWB_CIRDIAG=1 -DCONFIG_ULTRAWIDELOCK_CRED=1 \
   -DCONFIG_IDF_TARGET_ESP32C6=1 \
   -DCONFIG_FREERTOS_NUMBER_OF_CORES=1 \
   -DCONFIG_ESP_DEFAULT_CPU_FREQ_MHZ=160 \
   -I "$SDKFAKE" -I "$ESP_COMPONENTS/ultrawidelock_uwb/port" \
   -I "$UWB_INC" \
   -I "$HERE/../../../modules/ultrawidelock_dw3000/include" \
   -I "$HERE/../../../modules/ultrawidelock_dw3000/dwt_uwb_driver" \
   "$HERE/test_esp_dw3000_port.c" \
   "$ESP_COMPONENTS/ultrawidelock_uwb/port/dw3000_hw.c" \
   "$ESP_COMPONENTS/ultrawidelock_uwb/port/dw3000_spi.c" \
   "$SDKFAKE/fake_driver.c" "$SDKFAKE/fake_freertos.c" -o "$DBIN"
"$DBIN"
rm -f "$DBIN"

echo
echo "== host: seam RX-callback shim chaining =="
SBIN2="$(mktemp -t esp_seam_stubs.XXXXXX)"
cc -std=c11 -O1 -Wall -Wextra -DCONFIG_ULTRAWIDELOCK_UWB_CIRDIAG=1 -DCONFIG_ULTRAWIDELOCK_CRED=1 \
   -I "$HERE/../../../modules/ultrawidelock_dw3000/dwt_uwb_driver" \
   -I "$UWB_INC" \
   "$HERE/test_esp_seam_stubs.c" \
   "$ESP_COMPONENTS/ultrawidelock_uwb/port/ultrawidelock_seam_stubs.c" -o "$SBIN2"
"$SBIN2"
rm -f "$SBIN2"

echo
echo "== host: matter-lock app glue vs CHIP/esp-matter fakes =="
# The six esp-matter door-lock app sources compiled UNMODIFIED against the
# matterfake/ CHIP + esp-matter recording doubles (C++17). Proves branch
# logic + argument plumbing only — never CHIP-stack, NimBLE, hardware, or
# crypto truth. lock_led.c and the shared ultrawidelock_approach controller are C, so
# they get their own objects first (app_main.cpp drives the approach controller).
MFAKE="$HERE/matterfake"
LOCKD="$MATTER_MAIN"
MBIN="$(mktemp -t esp_matter_lock.XXXXXX)"
cc -std=c11 -O1 -w -c "$LOCKD/lock_led.c" -o "$MBIN.led.o"
cc -std=c11 -O1 -w -I "$CRED/include" -c "$CRED/src/ultrawidelock_approach.c" -o "$MBIN.approach.o"
${CXX:-c++} -std=c++17 -O1 -w \
   -DCONFIG_ENABLE_ULTRAWIDELOCK_BLE_UWB=1 -DCONFIG_ULTRAWIDELOCK_CRED_LAB=1 -DCONFIG_ULTRAWIDELOCK_UWB_CIRDIAG=1 \
   -DCONFIG_ULTRAWIDELOCK_LAT_TRACE=1 -DCONFIG_IDF_TARGET_ESP32C6=1 -DULTRAWIDELOCK_PORT_HOST \
   -I "$MFAKE" -I "$SDKFAKE" -I "$LOCKD" -I "$LOCKD/lock" \
   -I "$CRED/include" -I "$ULTRAWIDELOCK_PORT_INC" \
   -I "$UWB_INC" \
   "$HERE/test_esp_matter_lock.cpp" \
   "$LOCKD/app_driver.cpp" "$LOCKD/app_main.cpp" "$LOCKD/app_shell.cpp" \
   "$LOCKD/lock/door_lock_manager.cpp" "$LOCKD/lock/door_lock_callbacks.cpp" \
   "$LOCKD/lock/ultrawidelock_reader_delegate.cpp" \
   "$MFAKE/matterfake.cc" "$MBIN.led.o" "$MBIN.approach.o" -o "$MBIN"
# pipefail keeps the binary's exit status; the grep hides app_main's own
# onboarding-code printf noise without dropping any ok/FAIL/RESULT line.
"$MBIN" | grep -E '^(--|  ok|  FAIL|RESULT)'
rm -f "$MBIN" "$MBIN.led.o" "$MBIN.approach.o"

echo
echo "== target: port build + link-seam guard =="
bash "$HERE/verify_port.sh"
