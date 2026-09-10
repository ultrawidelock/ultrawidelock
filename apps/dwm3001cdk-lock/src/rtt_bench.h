/* SPDX-License-Identifier: ISC */

/*
 * rtt_bench.h - bench commands typed into the RTT terminal.
 *
 * The Matter image has no shell: RTT is its only console and the USB
 * provisioning console is compiled out (overlay-thread.conf). But RTT has a
 * down-buffer, and `make monitor` (probe-rs) feeds what you type at its
 * `Terminal>` prompt into down-buffer 0. This drains it for the one line the
 * ESP32 lock has always had as `ultrawidelock prov`:
 *
 *   prov    print identity, trust store, issuer keys, last-presented credential
 *
 * Bench only. A `trust` line (admit whichever credential was presented last)
 * lived here briefly for a second device on the owner's Apple ID, which the
 * hub never sends a SetCredential for; the reader now learns such a key from
 * the device's Access Document instead, and this image had no flash for both.
 */

#ifndef RTT_BENCH_H_
#define RTT_BENCH_H_

#ifdef __cplusplus
extern "C" {
#endif

/** Drain RTT down-buffer 0 and run any complete command line. Cheap when
 *  nothing is attached: one SEGGER_RTT_Read that returns 0. */
void rtt_bench_poll(void);

#ifdef __cplusplus
}
#endif

#endif /* RTT_BENCH_H_ */
