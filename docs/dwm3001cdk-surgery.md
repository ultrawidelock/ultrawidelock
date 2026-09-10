# DWM3001CDK surgery

Non-obvious findings from putting a **hand-written Matter node** beside the credential
UWB reader on a DWM3001CDK (nRF52833 + DW3110, NCS v3.3.0 / Zephyr). Goal: factory to
walk-up unlock **and a working Home tile** with nothing but the Home app: no build-time
key, no donor ESP32, nothing typed in.

The nRF52833 has **128 KB of RAM**, and almost every trap below is either that constraint
or a consequence of writing the Matter node by hand rather than linking CHIP. The other
port: [`esp32-gotchas.md`](esp32-gotchas.md).

Code lives under [`firmware`](../apps/dwm3001cdk-lock), the portable Matter node in
`modules/ultrawidelock_matter`, and the reader in `modules/ultrawidelock_cred` (shared byte-for-byte with
the ESP32 port, see §9.2).

> Verification convention: **VERIFIED** = observed on this silicon; **MEASURED** = a
> number read off the target, not estimated; **PREDICTED** = derived from source or spec
> and never observed here, so a hazard to measure rather than a finding.

---

## 1. RAM is the binding constraint, and it bites as stack overflows

### 1.1 The budget, measured

**MEASURED.** Reader + hand-written Matter node + Thread MTD/MED, in the
`RELEASE=1 SMP=1` image after the five-fabric transaction work:
**120,740 B of 131,072 B (92.12%)**, 10,332 B free. Application flash is
397,360 B of 433,664 B (91.63%). The like-for-like increase against clean
`main` is 4,992 B of RAM and 8,560 B of flash; both builds used NCS v3.3.0,
Zephyr 4.3.99, LTO, release logging, and SMP.

After the speed/robustness work the same image measures **118,312 B RAM (90.3%)** and
**417,684 B of the 433,664 B `app` partition (96.3%)**: roughly 12.8 KB of RAM spare
against 15.6 KB of flash. RAM was reclaimed and flash was spent, so **flash is now the
binding constraint** and the one to check first.

**127,352 B has been recorded as unrunnable on this board.** An observation, not a spec:
builds above it have failed to come up, so treat it as a ceiling. Every RAM change needs
a boot check (§8.4); the ECDH self-test line proves the image is alive:

```
*** Booting nRF Connect SDK v3.3.0 ***
ECDH self-test: PASS (NIST CAVP P-256 CDH count 0)
```

### 1.2 Three different stacks overflowed, all from adding one feature

**VERIFIED.** Adding persistence to the Matter node produced three MPU stack-guard faults
on three different threads over a few hours. None was diagnosable from the symptom, and
two presented as something else entirely:

| Stack | Measured peak | What the default bought | Symptom |
|---|---|---|---|
| system work queue | **3,872 B** | 4096 left **224 B** | fault mid-unlock, right after `SENT_AUTH0` |
| `ot_work_q` (the Interaction Model) | **3,072 B** | 3168 default left **96 B** | paired once, then halted at `CommissioningComplete` |
| `z_main_stack` | not measured | 4096, blown by a 1,642 B frame | board advertised, froze 4 s into boot |
| `matter_wq_stack` | 2,776 B of 4,096 | healthy | measuring it is what *ruled it out* |

**A default is a starting point, not a size.** Two of the three were within a few hundred
bytes of fitting, and a margin that thin fails only when something else runs at the same
moment: identical firmware worked for weeks, then failed twice in an evening.

### 1.3 Read the paint; never estimate

**VERIFIED.** `CONFIG_INIT_STACKS=y` fills stacks with `0xAA` and costs nothing at
runtime. A debugger reads the high-water mark straight out of RAM:

```sh
# addresses from build-*/app/zephyr/zephyr.map
JLinkExe … -CommandFile <(printf 'savebin s.bin, 0x20015900, 0x1040\nq\n')
# skip the 64 B MPU guard at the low end, count the leading 0xAA run:
#   peak = (size - guard) - run
```

`CONFIG_THREAD_ANALYZER_AUTO` measures the same paint and costs a thread plus its stack:
enabling it took an image to 96.6% RAM and past the unrunnable figure. **Use the paint,
not the analyzer**, on this part.

Two traps when reading it:

- The MPU guard occupies the first 64 B and is never painted. Counting `0xAA` from
  offset 0 reports "100% used" on a healthy stack.
- **Symbol addresses move with every BSS change.** A stale address reads as garbage, and
  a stale `last_count` (§8.3) reads as a *hung board*. Re-read from the map after every
  build.

### 1.4 Where the bytes went, and the cheap reclaims

**MEASURED.** Two changes cost far more than they looked:

- Raising `ULTRAWIDELOCK_TRUST_MAX` 4 → 8 grew `ULTRAWIDELOCK_PROV_BLOB_MAX` 476 → 864 B **and**
  `struct ultrawidelock_trust_store` 390 → 778 B. A function holding both had a 1,642 B frame,
  which went through the bottom of the 4 KB main stack. Fix: the blob is `static`, and
  the cap settled at 6.
- A `struct matter_im_read` made `static` to describe **one** attribute costs ~264 B,
  because it carries `MATTER_IM_MAX_PATHS`. On the stack instead, on a work queue with
  measured headroom.

Rule on this part: **large single-use objects belong on a stack with known headroom, not
in BSS**, once that headroom is measured.

---

## 2. Matter state must not be written from the OpenThread thread

**VERIFIED.** Matter datagrams arrive through the OpenThread UDP callback, so the whole
Interaction Model (decrypt, decode, cluster command, response encode, framing) runs on
`ot_work_q`. Two failures came from that:

1. **An NVS write there overflows it.** `CommissioningComplete → store fabrics → NVS`
   faulted after both fabrics were accepted, both CASE sessions established and the
   subscription primed. The pairing succeeded on the wire and failed anyway.
2. **A write anywhere in a handshake stalls it.** Storing at `AddNOC` wrote ~1.7 KB
   across several settings keys; an NVS sector erase on this part runs to tens of
   milliseconds. The commissioner retransmitted Sigma1 and the second fabric's CASE died
   with `Sigma3 REJECTED (-6)` ×5, then `RemoveFabric`.

**Rule: prepare only provisional state before `CommissioningComplete`, then cross a
durability boundary on the system work queue before returning success.** The OpenThread
callback waits on a bounded semaphore and never writes NVS itself, so a failed persistence
operation fails the command instead of acknowledging an identity that will disappear after
reset.

Each attempt owns only the slots and staged Thread data it created. Completion promotes
those to committed; fail-safe expiry clears only the provisional slots. An established
Apple fabric is no longer collateral damage when a later Home Assistant commissioner
aborts.

---

## 3. A subscription the node can serve needs four things

> What the node sends once a subscription exists, both events and the ring that
> holds them, is [`matter-door-lock-events.md`](matter-door-lock-events.md).

**VERIFIED.** "Matter Accessory / No Response" and a Home tile stuck spinning on
*Unlocking* were four independent bugs, each looking like the whole problem.

### 3.1 The priming report must fit the IPv6 MTU

`MATTER_MAX_MESSAGE_LEN` (1232) is the ceiling for the **whole message**, 1280 less the
IPv6 and UDP headers, so the exchange headers (36) and the AEAD tag (16) come **out** of
it, not on top. Spending all 1232 on the payload builds a datagram up to 52 bytes over
the MTU.

Nothing logs: the framing succeeds, the send returns, and the datagram is never delivered,
so the subscriber re-subscribes forever and the CASE table churns.

**BLE hides this.** BTP re-fragments, so the identical report crosses a commissioning
session intact and only Thread-carried subscriptions fail: an accessory that works while
pairing and dies immediately after. **Tell it apart by which transport the established
subscription sat on**, not by whether one established at all.

### 3.2 The node must be able to *initiate* an exchange

Everything a responder-only node sends answers something. After the priming report the
**server** has to speak unprompted, and a controller that gets no report calls the
accessory unresponsive however healthy the session is.

The session role is unchanged, so this is cheap: keys stay role-relative to CASE (still
encrypt with `r2i`) and the message counter is per-session, not per-exchange. Only the
exchange role differs: set `I`, use an id of your own, and **do not** write it back over
the peer's live exchange id.

Three subtleties, all found by tests rather than by reading the code:

- **Never piggyback the peer's pending ack onto an exchange you just opened.** An ack
  names a counter *within* an exchange.
- **Do not clear `ack_pending` on that path.** Clearing an ack that was never encoded
  makes the peer retransmit a message already handled, and the exchange that owes the ack
  stalls.
- **Acknowledge a subscription report's StatusResponse on the report's OWN exchange,
  with `I` set.** CHIP matches an inbound message to an exchange by id *and* by the
  initiator flag being the opposite of its own (`ExchangeContext::MatchExchange`), so an
  ack framed with `I` clear on the peer's exchange id matches nothing, is dropped as
  unsolicited, and the peer retransmits the message being acknowledged. Every
  `LockState` report drew the full MRP schedule until `matter_exchange_ack_initiator()`
  existed.

### 3.3 Report on change

The tile reads `LockState`, not the InvokeResponse. A controller takes the `SUCCESS` then
waits for the attribute to be reported before the UI moves, so answering the command and
stopping there is a lock that opens and a UI that spins forever.

### 3.4 Report on a **timer**, not only on change

Matter's contract is a report at least every `max_interval` whether or not anything
changed (600 s is what Apple asks for here). Reporting only on change means **a lock
nobody touches for ten minutes stops existing**.

One timer for all subscriptions, not one each: they carry the same attribute, the interval
is a floor not a schedule, and six timers are unnecessary at 92.12% RAM. 120 s is early on
purpose: a report is ~67 B on a link whose round trip measured 1.4 s, so early is nearly
free and late is the entire failure. Stop re-arming when nothing is subscribed, so a node
nobody watches is not waking its radio.

### 3.5 Bridge the reader's own state into `LockState`

**VERIFIED.** A walk-up unlock never touches the Door Lock cluster, being the reader's own
Aliro transaction, so the tile keeps showing whatever the last tile tap set. The Wallet
animates *unlocked* while the app says locked: the app is **uninformed**, not wrong.

Hook the point that sends the reader-status notification, because it carries **both**
transitions (the grant that fires the animation and the walk-away relock). Do **not** use
a credential-verdict callback: it fires on the unlock and never on the relock, so the
tile would show a lock that opens and never closes.

---

## 4. Persistence, and what must *not* be persisted

### 4.1 Nothing Matter-side was persisted at all

**VERIFIED.** The fabric table was plain RAM, so every reset silently un-commissioned the
node: it came back advertising commissionable, Thread never started because nothing
replayed the dataset, and the controller showed the accessory gone. Every flash cost a
full re-pair.

The image persists the fabrics, per-fabric ACLs, Thread dataset, xPAN id and the
ICAC slot. **Restore alone is not enough**: a restored identity is commissioned but
not *reachable* until the dataset is handed to the stack and one SRP instance per fabric
is registered. Commissioning does that pair as a side effect; the boot path has no
commissioner to trigger it.

### 4.2 Versioned per-slot records, not a table rewrite

The `mf2` namespace stores metadata, network state, one record per fabric, one ACL record
per fabric, and the shared ICAC. Each record is versioned, sealed, and written through the
backend's atomic replacement primitive. A removal writes a valid tombstone before
returning success, so a power cut cannot expose an older deleted fabric. One corrupt
fabric or ACL record is discarded without destroying its neighbours.

The fabric record also carries the fabric's `UpdateFabricLabel` string, so an image from
before that field cannot be restored: `record_read()` rejects any record whose stored
length is not the length it expects, so a pre-label identity is dropped at load and the
node comes back uncommissioned. One re-pair, once.

The serializer is a bounded 528 B static union, not an object on the OpenThread stack. The
settings region is 16 KB at `0x7c000`; Zephyr NVS and the FreeRTOS log use different media
formats but implement the same transaction contract.

### 4.3 Completion belongs to an attempt, not the node

The old global `commissioning_complete` boolean made fail-safe rollback a no-op as soon as
*any* administrator had completed. Two bitsets now distinguish committed slots from the
slots owned by the active attempt. The persistent records contain only committed fabrics,
so a reboot cannot promote a half-added controller and a later PASE session cannot erase a
working one.

### 4.4 Erase SRP identity as one unit

Keeping a stable SRP host name while destroying its client key can make a border router
reject the new owner as `OT_ERROR_DUPLICATED`. The port persists the SRP key and
service-name identity together. Its registration slots have `live`, `removing` and `free`
lifetimes, and their OpenThread service structures are not reused until the asynchronous
removal callback returns them. A duplicate registration is retried with a fresh service
name instead of being logged as false success.

`make flash-erase` clears commissioning and reader state. Use controller `RemoveFabric`
for one administrator and SW2 only for an unreachable last-resort reset.

### 4.5 An erase that cannot fail visibly

**VERIFIED.** Discarding every `settings_delete()` return behind `(void)` and logging
"erased" unconditionally made a wipe that removed **nothing** indistinguishable from one
that worked: a board kept coming back with the same fabrics. Report each key's `rc`.

---

## 5. Advertising: one payload, one gate, and three ways to lose it

### 5.1 Only one payload fits a legacy advert

**VERIFIED.** Flags (3) + Matter service data (12) + Aliro service data (26) = 41 bytes of
the 31 available. A second advertising set costs ~24.8 KB of RAM, which this part does not
have. So the node advertises **commissionable while it holds no fabric, and Aliro only
once it does**.

### 5.2 Restarting advertising from the disconnect callback fails

**VERIFIED.** `bt_le_adv_start()` returns **`-12` (`-ENOMEM`)** when called from inside
the `disconnected` callback: Zephyr has not released the connection object yet. Defer it
to a work item and retry.

The advert logged only on success, so a failed restart left the reader invisible with
nothing in the log but the "re-advertising" line. The board unlocked once then ignored
every approach **while the Home tile kept working**, because Matter runs over Thread and
this is BLE. An advertising failure must never be quiet: it presents as dead hardware and
points the investigation everywhere except at advertising.

### 5.3 Matter provisioning must refresh the advertisement

**VERIFIED, and it hid for weeks.** A phone resolves a reader by a dynamic tag derived
from the **GRK**. The reader starts advertising long before `SetAliroReaderConfig`
arrives, since the controller sends it as a post-commissioning operational command, so at
start the GRK is the dev default's all zeros and only the bare `0xFFF2` UUID goes out.

Without an explicit refresh the board ends up provisioned, holding both credentials,
reachable over Matter, tile working, **and invisible to every walk-up**.

**A reboot hides it**, because the boot path applies the stored GRK before it advertises
at all, and every earlier test power-cycled after pairing. It surfaced only when a reboot
happened *before* a pairing.

### 5.4 The advert gate must be re-run after a restore

The advert is chosen at BLE start, **before** stored fabrics are loaded. Without re-running
it, a restored reader keeps advertising commissionable and never offers `0xFFF2` again:
a node that unlocks until its first reboot and silently stops after it.

---

## 6. The trust store, and the issuer/endpoint key trap

### 6.1 A full store must evict, not refuse

**VERIFIED.** An Apple home installs **two endpoint keys per pairing**; they accumulate
and nothing removed them. With a cap of 4 the store filled on the second pairing, and
`trust_add()` answered a full store with a permanent refusal, so the key the phone
presents could never be added and pairing again only added more stale anchors. **No
recovery from that on a board with no console.**

Observed as 13 consecutive walk-ups reaching `device signature OK` then
`credential key NOT trusted`. The two apparent unlocks in that session went through the
expedited-fast path, which skips the trust check, so the store never matched a presented
key.

Evict a slot that has never completed a standard phase first (no `Kpersistent` means no
phone authenticated with it), then the oldest.

### 6.2 Log the operands, not just the verdict

"not in trust store" names the comparison but not what was compared. The two candidate
explanations, a credential never delivered versus stale anchors crowding out the current
one, are told apart **only by the bytes**. Print the presented key beside every anchor.

### 6.3 Credential types, and a conclusion that was wrong twice

**VERIFIED.** `SetCredential` delivers **type 6** (issuer key, correctly refused as an
anchor) and **type 7** (evictable endpoint key, stored). A pairing observed 3 calls:
one type 6, two type 7.

**Refused as an anchor, not as a key (2026-09-10).** The issuer key is now kept in its
own slots: it is what a device the hub never installed a key for -- an Apple Watch on the
owner's Apple ID -- proves itself against, through the step-up Access Document (see
CHANGELOG, "The Watch gets in without `trust`"). No phone ever presents it, so it still
never matches a walk-up on its own.

**An absence in a capture is evidence about the capture, not about the protocol.**
Captures showing only type 6 were captures of pairings that never got far enough to send
type 7: the subscription bug (§3.1) was stopping them.

---

## 7. A failed pairing used to be a brick

**VERIFIED on the old design, hit four times in one evening.** A commissioning could
install and persist a fabric, time out, and leave the advert gate offering Aliro `0xFFF2`
to a controller that had already forgotten the accessory.

Two recovery levels now. Fail-safe expiry rolls back only the active attempt, including
its staged Thread data, ACL, ICAC ownership, SRP service, sessions and subscriptions. A
fabric that did reach `CommissioningComplete` can be removed by an authenticated surviving
administrator; the targeted tombstone is durable before the success response.

Factory reset on **SW2 held through reset** remains the last resort when no administrator
can reach the node. `led0` blinks to confirm the hold, the reader identity, every trust
anchor and every Matter fabric are erased, and the boot continues commissionable. It is no
longer the normal response to a failed share.

Recovering a board without that button (older images): a one-boot clear flag, flashed once
and then flashed away.

---

## 8. Debugging on this board

### 8.1 Poll the RTT ring with `JLinkExe`

**VERIFIED, after two wrong turns.**

- **`JLinkGDBServer` is wrong here**: it disturbs the target enough to stop BLE, and
  pairing then fails with the phone stuck on "connecting". Flowing RTT does **not** prove
  the core is running: that argument was made and was wrong.
- **`JLinkRTTLogger` only works in the foreground**, so any keystroke kills the capture,
  and it degrades to "RTT Control Block not found" on every invocation until the board's
  USB is **replugged** (nothing in software cures it).
- **`JLinkExe` never failed**, including while the logger was broken, and is
  non-interactive so it backgrounds cleanly.

Read `WrOff`/`RdOff`, `savebin` the ring, slice host-side for the wrap, then **write
`RdOff` back**. Without the write-back the ring fills and `NO_BLOCK_SKIP` discards
everything new, which looks like a board that stopped logging.

Control block layout from the map: `aUp[0] = _SEGGER_RTT + 24`, then
`sName/pBuffer/SizeOfBuffer/WrOff/RdOff` at `+0/+4/+8/+12/+16`.

### 8.2 Make a failed probe read loud

Silently continuing on a read error makes a broken J-Link indistinguishable from a quiet
board.

### 8.3 Prove liveness independently

Read `nrf_rtc_timer`'s `last_count` twice: it advances at 32,768 Hz iff the kernel runs.
**Re-read its address from the map after every build**: a stale address returns a constant
and reads as a hung board (this produced exactly one false "STILL HUNG").

For a fault, halt and read `IPSR`: `004` is MemManage. Compare the faulting `SP` against
the stack regions in the map. An `SP` *below* a stack's base is that stack overflowing.

### 8.4 Prove reachability independently of the controller

`dns-sd -B _matter._tcp local` shows the operational services; `dns-sd -Gv6 <host>.local`
gives the address; `ping6` settles it. **0% loss while the controller reports "No
Response" means the problem is above basic Thread reachability.** The DWM image is an
rx-on MED, not a sleepy end device.

The border router caches mDNS records, so stale instances from earlier failed pairings
linger and are not evidence of anything.

---

## 9. Controller behaviour, and how to test against it

### 9.1 Every reboot costs ~10 minutes of controller sulk

**VERIFIED, and it is not a bug to fix.** Matter subscriptions are RAM on both sides.
After a reset the controller keeps retransmitting into sessions the node lost, visible as
`encrypted for session 0xNNNN, which is not ours`, and re-subscribes only when its own
`max_interval` expires.

**The node cannot force it.** The exchange id needed to answer is inside ciphertext it has
no key for. (An earlier claim that a real node replies with a StatusReport was withdrawn;
CHIP drops these too.)

> **Batch changes and test once.** Flashing after each change resets the very state the
> previous change needed to prove itself. Eight flashes in an hour demonstrated this the
> expensive way: three separate fixes were built, flashed and left unproven because each
> flash restarted the controller's timeout.

**The controller also provisions late.** Credentials have landed ~40 minutes after the
pairing UI finished. A capture shorter than the wait will say it never happened.

### 9.2 `modules/` is shared: run **both** suites

**VERIFIED.** A change under `modules/ultrawidelock_cred` was validated against the host
suite only. The ESP32 suite, the *only* one that builds `ultrawidelock_reader.c`, had been
broken by it two commits earlier and nobody noticed:

```sh
make test                  # host suite
./tests/ports/esp32/run.sh  # host-compiled, no ESP-IDF, no hardware, seconds
```

When behaviour changes deliberately, **update the stale assertions to the new behaviour
rather than silencing them**: a test asserting that a full trust store refuses is
asserting the bug §6.1 exists.

### 9.3 A test proves nothing until it has been seen to fail

House rule: revert the fix, confirm the exact checks fail, restore. Two real bugs in
§3.2 were found this way and not by reading.

### 9.4 Check exit codes, not output

A build reported success because the pipeline ended in `tail`, and the failure was
invisible. Write to a file and test `$?`.

---

## 10. What is still open

- **`CONFIG_ULTRAWIDELOCK_PROV_CLEAR_ON_BOOT` does not apply.** Set in `prj.conf` *or* an overlay
  it still leaves `# CONFIG_… is not set` in `.config`, with **no Kconfig warning**, while
  a symbol added 22 lines later in the same file applies fine. The symbol has no
  `depends on` and no enclosing `if`/`menu`. Unexplained. Workaround: force the
  `#if IS_ENABLED(...)` to `#if 1` for one boot, then revert.
- **Apple Home plus Home Assistant hardware fault injection.** Five-fabric,
  rollback, removal, response-replay, persistence, Thread-staging, and SRP
  behavior are host-tested and the DWM image builds and fits. The live
  CDK-19 through CDK-26 rows in `hardware-validation.md` have not run.
- **One ICAC owner.** Five fabrics fit, but the RAM-bounded portable table has
  one shared ICAC buffer. A second fabric that requires its own intermediate
  certificate is rejected without mutating the existing owner.
- **RAM at 90.3%, flash at 96.4%.** About 15 KB spare in the `app` partition
  against roughly 13 KB of RAM. Measure before adding: a new static allocation
  is now a smaller decision than a new code path.

## 11. Three bugs the host suite could not see

All three shipped in the speed/robustness work, all three passed `make check`
with thousands of assertions green, and all three stopped the walk-up dead on a
real DWM3001CDK.

**The pattern: a fixture that agrees with itself proves nothing.** Each bug compared a
value derived by a helper against the same value as it arrives on air. The host tests
built *both sides* from that helper, so the fixture agreed with itself whatever byte order
the code chose.

1. **KeySource compared in the wrong byte order.** `ccc_uad_addresses()` emits
   `KeySourceHigh || KeySourceLow`; `ccc_parse_mhr()` copies the Aux Security
   Header field in transmission order, which is the reverse. A straight `memcmp`
   rejected every Pre-POLL. Observed: `uad ks=0f3795ed` against `hdr ks=ed95370f`.
2. **DestShort assembled little-endian instead of MSB-first.** Same function, same
   root cause, and it survived the first fix because the diagnostic printed the
   two halves in different formats: `uad dest=02ff | hdr dest=02ff` is the byte
   pair `02 ff` against the u16 `0x02ff`, which read the other way is `0xff02`.
   They were never equal. **Print two things being compared the same way.**
3. **`ranging_block` compared against a stale snapshot.** The block number reaches
   the receiver through the *deferred* Pre-POLL decode, while the Final evidence
   is snapshotted synchronously in the Final RFRAME callback. The two are one
   block apart whenever the stash has not drained: `blk=2 want=1`, with session id
   and STS index both matching. The check was dropped rather than
   repaired: `final_sts_index` derives from `g_armed_index`, increments once per
   block, and binds the round more tightly than a 16-bit counter does.

**Symptoms.** Bugs 1 and 2 present as `tx0` in the `⟐` heartbeat with
`sts●`: frames arrive, none are answered, no `· NNcm` ever appears, and the
session dies on `credential phase deadline expired`. `tx0` puts the fault at or
before POLL: the Response was never armed. Bug 3 presents as healthy
`tx` and a healthy error ratio with still no `· NNcm`.

**Why none of it was visible.** Every reject path in `ccc_shim_rx.c` reports
through `DIAGK`, which a pretty-shell build compiles to nothing, so a rejected
Pre-POLL had no observable at all. Look first for the
`Pre-POLL accepted: URSK proven on air` line; if it is absent, the gate ahead of
it is rejecting, and promoting the reject paths to `ultrawidelock_printf`
temporarily identifies which.
