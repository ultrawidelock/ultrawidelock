/* SPDX-License-Identifier: ISC */

/*
 * rtt_bench.h - bench commands typed into the RTT terminal.
 *
 * The Matter image has no shell: RTT is its only console and the USB
 * provisioning console is compiled out (overlay-thread.conf). But RTT has a
 * down-buffer, and `make monitor` (probe-rs) feeds what you type at its
 * `Terminal>` prompt into down-buffer 0. This drains it for two lines the
 * ESP32 lock has always had as `ultrawidelock trust` / `ultrawidelock prov`:
 *
 *   trust   trust the credential the last session presented, persist it
 *   prov    print identity, trust store, last-presented credential
 *
 * Bench only, and honest about it: a credential that was rejected as
 * "NOT trusted" is exactly the one `trust` admits, so type it only after the
 * device you meant to enrol was the last one to try. The Home hub is supposed
 * to deliver every endpoint key by SetCredential; this is for the ones it
 * did not (an Apple Watch, in every field log so far).
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
