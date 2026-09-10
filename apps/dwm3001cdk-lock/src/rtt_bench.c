/* SPDX-License-Identifier: ISC */

/* See rtt_bench.h. */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <ultrawidelock/reader.h>

#include "rtt_bench.h"

/*
 * The side gate's bench feed (CONFIG_ULTRAWIDELOCK_SIDE_FEED_RTT) drains the
 * same down-buffer for SF1 lines. Two readers on one buffer would each see
 * half of every line, so this one stands down when that one is built.
 */
#if defined(CONFIG_USE_SEGGER_RTT) && !IS_ENABLED(CONFIG_ULTRAWIDELOCK_SIDE_FEED_RTT)
#include <SEGGER_RTT.h>

static void run_line(const char *t)
{
	while (*t == ' ' || *t == '\t') {
		t++;
	}
	/* `trust` (admit whichever key was presented last) is gone from this image:
	 * a second device on the owner's Apple ID is learned from its Access
	 * Document now, and the flash it cost is the flash that learn path needed.
	 * The ESP32 shell keeps `ultrawidelock trust` for the bench. */
	if (strcmp(t, "prov") == 0) {
		ultrawidelock_reader_prov_print();
	} else if (*t != '\0') {
		printk("bench: unknown '%s' (prov)\n", t);
	}
}

void rtt_bench_poll(void)
{
	static char buf[32];
	static size_t len;
	unsigned n;

	if (len + 1 >= sizeof(buf)) {
		len = 0; /* an oversized line would otherwise wedge the reader */
	}
	n = SEGGER_RTT_Read(0, buf + len, (unsigned)(sizeof(buf) - 1 - len));
	if (n == 0) {
		return;
	}
	len += n;
	buf[len] = '\0';
	for (;;) {
		char *nl = strpbrk(buf, "\r\n");

		if (nl == NULL) {
			return;
		}
		*nl = '\0';
		run_line(buf);
		{
			size_t used = (size_t)(nl - buf) + 1u;

			memmove(buf, nl + 1, len - used);
			len -= used;
			buf[len] = '\0';
		}
	}
}
#else
void rtt_bench_poll(void)
{
}
#endif
