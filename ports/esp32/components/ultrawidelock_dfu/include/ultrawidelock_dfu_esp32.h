/* SPDX-License-Identifier: ISC */

/*
 * ultrawidelock_dfu_esp32.h - the ESP-IDF port of the over-the-air update path.
 *
 * Three calls, in the order an application makes them:
 *
 *   ultrawidelock_dfu_esp32_confirm()   early, once the image looks healthy
 *   ultrawidelock_dfu_esp32_init()      once, before the radio is up
 *   ultrawidelock_dfu_esp32_register_gatt()  from the NimBLE host, before it starts
 *
 * and one the board's button calls:
 *
 *   ultrawidelock_dfu_esp32_open_window()
 *
 * Everything else -- the frame protocol, the signature check, the CRCs, the
 * retry and ownership rules -- is modules/ultrawidelock_dfu, shared verbatim
 * with the DWM3001CDK and the standalone FreeRTOS port.
 */

#ifndef ULTRAWIDELOCK_DFU_ESP32_H_
#define ULTRAWIDELOCK_DFU_ESP32_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Install the commit hook that points the ROM bootloader at a staged image.
 *
 * Without this an update is received, verified, written to the spare slot --
 * and then ignored at the next boot, because nothing wrote otadata. Call it
 * once at start-up, before any transport can accept a frame.
 */
void ultrawidelock_dfu_esp32_init(void);

struct ble_gatt_svc_def;

/**
 * The service definition, for a NimBLE host somebody else owns.
 *
 * THIS IS THE ONE THE MATTER LOCK WANTS. On that image the host belongs to
 * CHIP: it counts and adds one table of its own and then starts the host, and
 * NimBLE's attribute table is built exactly once, at ble_gatts_start(). A
 * service added after that is queued onto a list that has already been walked
 * and freed -- it does not fail, it is simply not there.
 *
 * CHIP's hook is BLEMgrImpl().ConfigureExtraServices(vector, afterMatterSvc),
 * which must be called BEFORE esp_matter::start() and can only be called ONCE.
 * Every extra service on that board therefore has to go into the same vector:
 *
 *     std::vector<struct ble_gatt_svc_def> svcs;
 *     svcs.push_back(*ultrawidelock_reader_ble_prepare());
 *     svcs.push_back(*ultrawidelock_dfu_esp32_service_def());
 *     BLEMgrImpl().ConfigureExtraServices(svcs, true);
 *
 * The returned pointer is one element, not a null-terminated table: CHIP copies
 * it by value and supplies its own terminator.
 *
 * Touches nothing in the host: CHIP has not started it yet, and on ESP-IDF its
 * GAP state is not even allocated until it does. The disconnect listener that
 * drops a half-received transfer when its peer goes away is armed from the
 * service's first GATT write instead, on the started host's own task.
 */
const struct ble_gatt_svc_def *ultrawidelock_dfu_esp32_service_def(void);

/**
 * Register the DFU GATT service on a NimBLE host we brought up ourselves.
 *
 * For a standalone image -- one that called nimble_port_init() itself and has
 * not started the host yet. On a CHIP-owned host this returns BLE_HS_EBUSY or,
 * worse, succeeds and registers nothing; use service_def() there.
 *
 * Same service and characteristic UUIDs as the Zephyr and FreeRTOS ports, so
 * one host tool and one web page drive all three.
 *
 * @return 0 on success, negative if the service could not be added.
 */
int ultrawidelock_dfu_esp32_register_gatt(void);

/**
 * Open the update window for @p duration_ms.
 *
 * Until this is called the receiver refuses every frame, and THAT IS THE
 * AUTHORIZATION MODEL. The image is signed and the bootloader re-validates it,
 * so no peer can install code regardless; what the window prevents is an
 * unauthenticated peer in radio range erasing a 3 MB slot and forcing reboots.
 * A door lock anyone nearby can reboot in a loop is a real availability attack,
 * and a window the owner has to open by hand is what stops it.
 */
void ultrawidelock_dfu_esp32_open_window(uint32_t duration_ms);

/**
 * Tell the bootloader this image is healthy, cancelling a pending rollback.
 *
 * A no-op unless CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE is set, so it is safe to
 * call unconditionally. Call it from the point in start-up where the board is
 * doing its job -- not from the first line of app_main, which proves only that
 * the image links.
 *
 * @return 0 when there was nothing to do or the image was confirmed.
 */
int ultrawidelock_dfu_esp32_confirm(void);

#ifdef __cplusplus
}
#endif

#endif /* ULTRAWIDELOCK_DFU_ESP32_H_ */
