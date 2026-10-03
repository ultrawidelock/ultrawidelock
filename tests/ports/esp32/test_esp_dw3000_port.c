/*
 * Host test for the ESP-IDF DW3000 backend (components/ultrawidelock_uwb/port/
 * dw3000_hw.c + dw3000_spi.c) against the sdkfake GPIO/SPI recording doubles.
 * "Theatre" suite: no bus and no chip exist, so passing proves the transaction
 * framing (header/body/crc layout, 64-byte chunking inside one CS window, RX
 * body extraction), CS/RST/WAKEUP pin choreography as seen by the fake
 * registers, and the IRQ service-loop wiring — not SPI signal integrity or
 * DW3000 behavior. dwt_isr()/dwt_checkidlerc() are one-line doubles here.
 */
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "board_pins.h"
#include "dw3000_hw.h"
#include "dw3000_spi.h"

extern volatile uint32_t g_dw_cyc_per_us;

#if CONFIG_FREERTOS_NUMBER_OF_CORES > 1
#define EXPECTED_UWB_CORE 1
#else
#define EXPECTED_UWB_CORE 0
#endif

/* uwb_cirdiag_flush double: dw3000_hw's ISR task calls it after draining IRQs;
 * the real emitter lives in the ultrawidelock_uwb driver, out of this port suite. */
void uwb_cirdiag_flush(void)
{
}

static int fails;

static void okc(const char *name, int cond)
{
	if (!cond) {
		printf("  FAIL %s\n", name);
		fails++;
	} else {
		printf("  ok   %s\n", name);
	}
}

/* ---- decadriver doubles (prototypes as in deca_device_api.h) -------------- */
static int s_dwt_isr_calls;
static uint8_t s_idlerc; /* what dwt_checkidlerc reports */

void dwt_isr(void)
{
	s_dwt_isr_calls++;
}

uint8_t dwt_checkidlerc(void)
{
	return s_idlerc;
}

uint32_t dw3000_dwt_cyccnt(void); /* exported by dw3000_hw.c for the driver diag */

/* ---- IRQ service-loop pump ------------------------------------------------ */
static jmp_buf s_pump_out;
static int s_takes;

static BaseType_t take_once(SemaphoreHandle_t s, TickType_t ticks)
{
	(void)s;
	(void)ticks;
	if (s_takes++ > 0) {
		longjmp(s_pump_out, 1); /* second wait: leave the forever-loop */
	}
	return pdTRUE;
}

static void drop_irq_line(int pin)
{
	if (pin == ULTRAWIDELOCK_DW3000_PIN_IRQ) {
		fake_gpio_input_level[pin] = 0; /* one dwt_isr pass, then done */
	}
}

static void t_spi_init(void)
{
#if CONFIG_IDF_TARGET_ESP32C6
	okc("C6 pin map",
	    ULTRAWIDELOCK_DW3000_PIN_SCLK == 6 && ULTRAWIDELOCK_DW3000_PIN_MOSI == 7 &&
	    ULTRAWIDELOCK_DW3000_PIN_MISO == 2 && ULTRAWIDELOCK_DW3000_PIN_CS == 10 &&
	    ULTRAWIDELOCK_DW3000_PIN_RST == 1 && ULTRAWIDELOCK_DW3000_PIN_IRQ == 3 &&
	    ULTRAWIDELOCK_DW3000_PIN_WAKEUP == 0);
#elif CONFIG_IDF_TARGET_ESP32S3
	okc("S3 pin map",
	    ULTRAWIDELOCK_DW3000_PIN_SCLK == 12 && ULTRAWIDELOCK_DW3000_PIN_MOSI == 11 &&
	    ULTRAWIDELOCK_DW3000_PIN_MISO == 13 && ULTRAWIDELOCK_DW3000_PIN_CS == 10 &&
	    ULTRAWIDELOCK_DW3000_PIN_RST == 4 && ULTRAWIDELOCK_DW3000_PIN_IRQ == 5 &&
	    ULTRAWIDELOCK_DW3000_PIN_WAKEUP == 6);
#endif
	okc("cycle rate follows target CPU",
	    g_dw_cyc_per_us == CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);

	printf("-- spi init --\n");

	fake_driver_reset();
	fake_spi_cs_pin = ULTRAWIDELOCK_DW3000_PIN_CS;

	fake_spi_bus_init_rc = ESP_FAIL;
	okc("bus init failure", dw3000_spi_init() == -1);
	fake_spi_bus_init_rc = ESP_OK;
	fake_spi_add_device_rc_slow = ESP_FAIL;
	okc("slow add failure", dw3000_spi_init() == -1);
	fake_spi_add_device_rc_slow = ESP_OK;
	fake_spi_add_device_rc_fast = ESP_FAIL;
	okc("fast add failure", dw3000_spi_init() == -1);
	fake_spi_add_device_rc_fast = ESP_OK;

	okc("init ok", dw3000_spi_init() == 0);
	okc("CS output + idle high",
	    fake_gpio_mode[ULTRAWIDELOCK_DW3000_PIN_CS] == GPIO_MODE_OUTPUT &&
	    fake_gpio_level[ULTRAWIDELOCK_DW3000_PIN_CS] == 1);
	okc("bus pins wired",
	    fake_spi_bus_cfg.mosi_io_num == ULTRAWIDELOCK_DW3000_PIN_MOSI &&
	    fake_spi_bus_cfg.miso_io_num == ULTRAWIDELOCK_DW3000_PIN_MISO &&
	    fake_spi_bus_cfg.sclk_io_num == ULTRAWIDELOCK_DW3000_PIN_SCLK);
	okc("re-init is a no-op", dw3000_spi_init() == 0 && fake_spi_bus_inits >= 1);
}

static void t_spi_framing(void)
{
	printf("-- spi transaction framing --\n");

	/* Read: 2-byte header, 8-byte body, single burst, CS low during. */
	uint8_t hdr[2] = {0x40, 0x02};
	uint8_t body[8];

	memset(fake_spi_miso, 0, sizeof(fake_spi_miso));
	for (int i = 0; i < 8; i++) {
		fake_spi_miso[2 + i] = (uint8_t)(0xA0 + i); /* body after the header */
	}
	fake_spi_txn_count = 0;
	okc("read rc", dw3000_spi_read(2, hdr, 8, body) == 0);
	okc("read = one 10-byte burst",
	    fake_spi_txn_count == 1 && fake_spi_txns[0].bytes == 10);
	okc("read header on MOSI", memcmp(fake_spi_txns[0].tx, hdr, 2) == 0);
	okc("read body zero-filled on MOSI",
	    fake_spi_txns[0].tx[2] == 0 && fake_spi_txns[0].tx[9] == 0);
	okc("read CS low during burst", fake_spi_txns[0].cs_level_during == 0);
	okc("read CS released after", fake_gpio_level[ULTRAWIDELOCK_DW3000_PIN_CS] == 1);

	int body_ok = 1;

	for (int i = 0; i < 8; i++) {
		body_ok = body_ok && body[i] == (uint8_t)(0xA0 + i);
	}
	okc("read body extracted from MISO", body_ok);

	/* Write: header + body bytes verbatim. */
	uint8_t wbody[5] = {1, 2, 3, 4, 5};

	fake_spi_txn_count = 0;
	okc("write rc", dw3000_spi_write(2, hdr, 5, wbody) == 0);
	okc("write framing", fake_spi_txn_count == 1 && fake_spi_txns[0].bytes == 7 &&
	    memcmp(fake_spi_txns[0].tx, hdr, 2) == 0 &&
	    memcmp(fake_spi_txns[0].tx + 2, wbody, 5) == 0);
	okc("write requests no RX", fake_spi_txns[0].rx_requested == 0);

	/* Write with CRC: trailing CRC8 byte after the body. */
	fake_spi_txn_count = 0;
	okc("write_crc rc", dw3000_spi_write_crc(2, hdr, 5, wbody, 0x9C) == 0);
	okc("crc byte appended", fake_spi_txns[0].bytes == 8 &&
	    fake_spi_txns[0].tx[7] == 0x9C);

	/* Chunking: 2 + 200 = 202 bytes -> 64+64+64+10 bursts, one CS window. */
	uint8_t big[200];

	for (size_t i = 0; i < sizeof(big); i++) {
		big[i] = (uint8_t)i;
	}
	fake_spi_txn_count = 0;
	okc("big write rc", dw3000_spi_write(2, hdr, 200, big) == 0);
	okc("chunked into 64-byte bursts",
	    fake_spi_txn_count == 4 && fake_spi_txns[0].bytes == 64 &&
	    fake_spi_txns[1].bytes == 64 && fake_spi_txns[2].bytes == 64 &&
	    fake_spi_txns[3].bytes == 10);
	okc("all bursts inside one CS window",
	    fake_spi_txns[0].cs_level_during == 0 && fake_spi_txns[3].cs_level_during == 0);
	okc("stream is contiguous across bursts",
	    fake_spi_txns[0].tx[2] == 0 && fake_spi_txns[1].tx[0] == 62 &&
	    fake_spi_txns[3].tx[9] == 199);

	/* Chunked read: MISO stream reassembled across bursts. */
	uint8_t rbig[100];

	for (size_t i = 0; i < sizeof(fake_spi_miso); i++) {
		fake_spi_miso[i] = (uint8_t)(i & 0xff);
	}
	okc("big read rc", dw3000_spi_read(2, hdr, 100, rbig) == 0);

	int stream_ok = 1;

	for (int i = 0; i < 100; i++) {
		stream_ok = stream_ok && rbig[i] == (uint8_t)((i + 2) & 0xff);
	}
	okc("chunked read reassembles the stream", stream_ok);

	/* Size guards + transmit failure. */
	okc("zero-length rejected", dw3000_spi_write(0, hdr, 0, NULL) == -1);
	okc("oversize rejected", dw3000_spi_write(2, hdr, 2047, NULL) == -1);
	fake_spi_transmit_rc = ESP_FAIL;
	okc("transmit failure -> -1", dw3000_spi_read(2, hdr, 4, body) == -1);
	okc("CS released after failure", fake_gpio_level[ULTRAWIDELOCK_DW3000_PIN_CS] == 1);
	fake_spi_transmit_rc = ESP_OK;

	/* Speed switch changes the device handle in use. */
	fake_spi_txn_count = 0;
	dw3000_spi_speed_slow();
	dw3000_spi_read(2, hdr, 1, body);
	dw3000_spi_speed_fast();
	dw3000_spi_read(2, hdr, 1, body);
	okc("slow/fast use different devices",
	    fake_spi_txn_count == 2 && fake_spi_txns[0].dev != fake_spi_txns[1].dev);
	okc("slow clock on slow device",
	    fake_spi_txns[0].dev->cfg.clock_speed_hz == ULTRAWIDELOCK_DW3000_SPI_SLOW_HZ &&
	    fake_spi_txns[1].dev->cfg.clock_speed_hz == ULTRAWIDELOCK_DW3000_SPI_FAST_HZ);

	/* CS-toggle wakeup: low, ~500 us, high. */
	fake_rom_delay_us_total = 0;
	dw3000_spi_wakeup();
	okc("wakeup toggled CS with 500 us low",
	    fake_gpio_level[ULTRAWIDELOCK_DW3000_PIN_CS] == 1 && fake_rom_delay_us_total == 500);

	dw3000_spi_trace_output(); /* no-op; just must link */
	okc("trace no-op", 1);
}

/* The clock of the device handle the next transfer goes out on. */
static int spi_hz_in_use(void)
{
	uint8_t hdr[2] = {0x40, 0x02};
	uint8_t body[1];

	fake_spi_txn_count = 0;
	dw3000_spi_read(2, hdr, 1, body);
	return fake_spi_txns[0].dev->cfg.clock_speed_hz;
}

static void t_hw(void)
{
	printf("-- hw init / reset / wakeup / irq --\n");

	okc("hw_init rc", dw3000_hw_init() == 0);
	okc("RST is input (released)", fake_gpio_mode[ULTRAWIDELOCK_DW3000_PIN_RST] == GPIO_MODE_INPUT);
	okc("WAKEUP output held high",
	    fake_gpio_mode[ULTRAWIDELOCK_DW3000_PIN_WAKEUP] == GPIO_MODE_OUTPUT &&
	    fake_gpio_level[ULTRAWIDELOCK_DW3000_PIN_WAKEUP] == 1);

	/* Reset choreography: drive low, release to hi-Z input. */
	dw3000_hw_mark_asleep();
	okc("marked asleep", dw3000_hw_is_asleep());
	fake_delay_calls = 0;
	dw3000_spi_speed_fast();
	dw3000_hw_reset();
	okc("reset released RST to input",
	    fake_gpio_mode[ULTRAWIDELOCK_DW3000_PIN_RST] == GPIO_MODE_INPUT &&
	    fake_gpio_level[ULTRAWIDELOCK_DW3000_PIN_RST] == 0);
	okc("reset waited (1+2 ticks)", fake_delay_total_ticks >= 3);
	okc("reset cleared asleep", !dw3000_hw_is_asleep());
	/* Out of reset the part is in INIT_RC, which only takes the slow clock. */
	okc("reset drops SPI to the slow clock",
	    spi_hz_in_use() == ULTRAWIDELOCK_DW3000_SPI_SLOW_HZ);

	/* Wakeup: no-op when awake; CS-wake + IDLE_RC poll when asleep. */
	fake_rom_delay_calls = 0;
	dw3000_hw_wakeup();
	okc("wakeup no-op when awake", fake_rom_delay_calls == 0);
	dw3000_hw_mark_asleep();
	s_idlerc = 1;
	dw3000_spi_speed_slow();
	dw3000_hw_wakeup();
	okc("wakeup ran CS-wake", fake_rom_delay_calls >= 1 && !dw3000_hw_is_asleep());
	okc("wakeup into IDLE_RC ends on the fast clock",
	    spi_hz_in_use() == ULTRAWIDELOCK_DW3000_SPI_FAST_HZ);
	dw3000_hw_mark_asleep();
	s_idlerc = 0; /* chip never reaches IDLE_RC: exhaust the 500-spin poll */
	fake_rom_delay_calls = 0;
	dw3000_hw_wakeup();
	okc("wakeup poll exhausts at 500 spins", fake_rom_delay_calls >= 500);
	okc("a part that never reached IDLE_RC stays on the slow clock",
	    spi_hz_in_use() == ULTRAWIDELOCK_DW3000_SPI_SLOW_HZ);
	s_idlerc = 1;

	dw3000_hw_wakeup_pin_low();
	okc("wakeup pin driven low", fake_gpio_level[ULTRAWIDELOCK_DW3000_PIN_WAKEUP] == 0);

	/* IRQ bring-up. */
	fake_gpio_isr_service_rc = ESP_FAIL;
	okc("isr-service failure", dw3000_hw_init_interrupt() == -1);
	fake_gpio_isr_service_rc = ESP_ERR_INVALID_STATE; /* already installed: fine */
	dw3000_spi_speed_slow();
	okc("init_interrupt rc", dw3000_hw_init_interrupt() == 0);
	/* The bring-up's last call, with the part initialised: fast from here on. */
	okc("radio up: SPI on the fast clock",
	    spi_hz_in_use() == ULTRAWIDELOCK_DW3000_SPI_FAST_HZ);
	okc("IRQ pin input + posedge",
	    fake_gpio_mode[ULTRAWIDELOCK_DW3000_PIN_IRQ] == GPIO_MODE_INPUT &&
	    fake_gpio_intr[ULTRAWIDELOCK_DW3000_PIN_IRQ] == GPIO_INTR_POSEDGE);
	okc("isr handler registered", fake_gpio_isr[ULTRAWIDELOCK_DW3000_PIN_IRQ] != NULL);
	okc("irq task uses target core at prio 23",
	    fake_task_count == 1 && fake_tasks[0].core == EXPECTED_UWB_CORE &&
	    fake_tasks[0].prio == 23);
	okc("interrupt reported enabled", dw3000_hw_interrupt_is_enabled());
	okc("re-init is idempotent", dw3000_hw_init_interrupt() == 0 && fake_task_count == 1);

	/* Fire the ISR, then pump the service task: dwt_isr while the line is high. */
	fake_gpio_isr[ULTRAWIDELOCK_DW3000_PIN_IRQ](fake_gpio_isr_arg[ULTRAWIDELOCK_DW3000_PIN_IRQ]);
	okc("isr yielded to the worker", fake_port_yields == 1);

	fake_gpio_input_level[ULTRAWIDELOCK_DW3000_PIN_IRQ] = 1;
	fake_gpio_get_level_hook = drop_irq_line;
	fake_sem_take_hook = take_once;
	s_takes = 0;
	s_dwt_isr_calls = 0;
	if (setjmp(s_pump_out) == 0) {
		fake_tasks[0].fn(fake_tasks[0].arg);
	}
	fake_sem_take_hook = NULL;
	fake_gpio_get_level_hook = NULL;
	okc("service loop ran dwt_isr once", s_dwt_isr_calls == 1);

	/* Enable/disable are edge-triggered on the tracked state. */
	dw3000_hw_interrupt_disable();
	okc("disable gates the GPIO intr",
	    !dw3000_hw_interrupt_is_enabled() &&
		    fake_gpio_intr_enabled[ULTRAWIDELOCK_DW3000_PIN_IRQ] == 0);
	dw3000_hw_interrupt_disable();
	okc("double disable no-op", !dw3000_hw_interrupt_is_enabled());
	dw3000_hw_interrupt_enable();
	okc("enable restores the GPIO intr",
	    dw3000_hw_interrupt_is_enabled() && fake_gpio_intr_enabled[ULTRAWIDELOCK_DW3000_PIN_IRQ] == 1);
	dw3000_hw_interrupt_enable();
	okc("double enable no-op", dw3000_hw_interrupt_is_enabled());

	/* Teardown: IRQ off, SPI devices removed, bus freed. */
	dw3000_hw_fini();
	okc("fini disables IRQ + frees SPI",
	    !dw3000_hw_interrupt_is_enabled() && fake_spi_removed_devices == 2 &&
	    fake_spi_bus_frees == 1);
	dw3000_spi_fini();
	okc("second spi_fini tolerated", fake_spi_removed_devices == 2);

	okc("cycle counter is monotonic", dw3000_dwt_cyccnt() < dw3000_dwt_cyccnt());
}

int main(void)
{
	fake_freertos_reset();

	t_spi_init();
	t_spi_framing();
	t_hw();

	printf("\nRESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
	return fails == 0 ? 0 : 1;
}
