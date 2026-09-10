# Changelog

What changed for someone running the firmware, not the commits that got it
there. `scripts/release-notes.sh` reads the section matching a tag and renders
it into that release's notes, so this file is the authored source and the git
log is only the fallback.

Versions follow [semantic versioning](https://semver.org). Dates are the day the
tag was cut.

## [Unreleased]

### ESP32-S3: pairing a fresh lock with Apple Home

- **"Unable to add Accessory" on a freshly erased board.** Home commissions a
  lock twice back to back (its phone's fabric, then its hub's, half a second
  apart), and the lock started its credential reader the moment the first
  round completed: from ~80 ms later every Wi-Fi send failed with lwIP
  `ERR_MEM` (`SendMessage() ... failed: 3000001`), the second round's reports
  never left the board, and Home gave up after its retries (measured
  2026-09-10, ESP-IDF v5.5.4). It regressed with the Watch change below:
  `88df5c7f`, the merge just before it, pairs cleanly with the very same
  reader start. The reader now waits until the commissioner has been quiet
  for 20 s: no further CommissioningComplete, no commissioning window open,
  no fail-safe armed. A commissioned lock rebooting starts the reader at
  once, as before.
- **`status` reports internal RAM:** free now, largest single block, and the
  least ever free since boot, so the headroom commissioning leaves is a number
  rather than a guess.
- **The satellite link no longer claims Matter's radio.** It told "already
  initialised" from `esp_wifi_init()` returning `ESP_ERR_INVALID_STATE`, which
  ESP-IDF 5.x never does (it answers `ESP_OK` on a radio someone else brought
  up), so on the lock it took the station for its own: it moved the Wi-Fi
  config store to RAM, where ESP-IDF keeps later credential changes out of
  NVS, and re-issued station mode and a start on Matter's running interface.
  It now asks `esp_wifi_get_mode()` first and only configures a radio nobody
  has initialised. Not the cause of the pairing failure above (`88df5c7f`
  pairs with it in place), but it was one reboot away from a lock forgetting
  a changed Wi-Fi password.

### The Watch gets in without `trust`

- **A second device on the owner's Apple ID is admitted through its Access
  Document.** Apple Home installs the home's credential issuer key
  (SetCredential type 6) and one endpoint key per iPhone, and never sends a
  SetCredential for a Watch on the same Apple ID (every field log so far: no
  `invoke: ... cluster 0x0101` line while the Watch retried). The Watch
  therefore presented a key no anchor matched and every approach ended in
  `credential key NOT trusted`. That is how Aliro means it to work, not a
  missing install: the certified Nordic reference lock keeps the issuer key
  and, when an unknown key is presented, requests the device's Access
  Document in the step-up phase, verifies the issuer signature, checks the
  document's `deviceKey` is the key the device just signed AUTH1 with, and
  stores the key (nRF Connect SDK door-lock add-on,
  `access_manager_impl.cpp`: `_ShouldRequestAccessDocument`,
  `_VerifyAccessCredential`, `ProcessAccessDocument`; Matter 1.4 names the
  same thing in `OperationSourceEnum` as "user change operation was a step-up
  credential provisioning as defined in [Aliro]"). Both boards now do the
  same. The issuer key is stored instead of dropped; a presented key no
  anchor matches is asked for its `matter1` document, and only a document a
  stored issuer signed over that very key learns it as an evictable endpoint
  anchor (type 7, next free index, the issuer's user) with its Kpersistent,
  so the next approach takes the ordinary fast path. The unlock waits on that
  verdict. A document that fails any §7.4 check, vouches for another key,
  brings its own certificate instead of a stored issuer, or is declined is
  rejected exactly as before, with the operands in the log. Clearing the
  issuer key (ClearCredential type 6, or ClearUser) revokes every key learned
  under it. The CDK's RTT `trust` command is gone with it (the image had no
  flash for both; `prov` stays); the ESP32 keeps `ultrawidelock trust` for
  the bench. Learned keys are not reported back over
  Matter, which matches the reference lock (its known issue AL-727: "User
  credentials provisioned in the Step-up phase ... are not exported to
  Matter"). Host tests walk the learn, the fast path after it, and each
  rejection (`tests/shared/test_ultrawidelock_reader.c`, section G).
- **`NumberOfAliroCredentialIssuerKeysSupported` now says 5, the number the
  reader actually holds**, and a sixth issuer is refused rather than evicted:
  an issuer is a trust root the admin placed, and dropping one silently would
  revoke every key it vouched for.
- **Provisioning blob v5.** Issuer keys and each anchor's issuer binding ride
  the same NVS record; v1 to v4 blobs still load, with no issuer and every
  anchor unbound. The record cap `ULTRAWIDELOCK_KV_VALUE_MAX` grows from 768
  to 1088 bytes, which the FreeRTOS port's three static record buffers
  follow.
- The step-up phase is built into both lock images now
  (`CONFIG_ULTRAWIDELOCK_CRED_STEPUP=y` in `prj.conf` and
  `sdkconfig.defaults`). `prov` lists the issuer keys and, per anchor, the
  issuer that vouched for it.

### Size limits in the credential reader fail loudly

- **A 0xA5 TLV the reader cannot hold ends the transaction with a named
  reason.** The phone's proprietary-information TLV in Initiate Access
  Protocol seeds the session-key salt; real phones send 10 bytes and the
  session keeps 64. One that used a long-form BER length, or outgrew the
  buffer, was silently treated as absent and the salt fell back to the CSA
  v1.0 default: a wrong key schedule, which surfaced much later as a GCM
  failure on AUTH1 that pointed nowhere near the cause. The reader now logs
  the length byte, terminates with `0xA5 TLV unusable`, and stops scanning at
  the first TLV it finds rather than reading into its value for another 0xA5.
  On the ESP32 bench, an Access Document that outgrows the 1,536-byte
  collection buffer was logged as "truncating" and kept collecting: later
  chunks that fit were appended and the gapped blob went to the verifier. It
  is now dropped on the first overflow, the buffer handed back at once, and
  the rest of the 61XX chain drained without a verdict (the CDK's learn path
  already rejected it). Value digests and disclosed items past the parser
  caps (12 and 8 on the CDK, 24 and 16 elsewhere) and text fields cut to 31
  characters were dropped without a trace; a docType over that length then
  failed the §7.4 step-4 compare as if it were the wrong type. They are still
  not errors (a real MSO lists more digests than the disclosed items), but
  the parsed document now counts them and flags which fields were cut, and
  the verdict line carries both (`drop=<digests>/<items> tr=<flags>`).

### Fixes for anyone running v0.5.0 on ESP32-S3

- **The image booted only with the update service turned off.** With
  `CONFIG_ULTRAWIDELOCK_DFU_ESP32=y` (the default) the board crashed in
  `app_main` before Matter started. The DFU service armed its NimBLE
  disconnect listener while handing its definition to CHIP, and on ESP-IDF
  the host's GAP state does not exist until CHIP starts it. The listener is
  now armed by the first write to the service instead. A host test pins the
  order.
- **`range` says how old the distance is.** The console kept printing the
  last distance a departed peer left behind ("170 cm" for a minute after the
  phone stopped ranging), which read as ranging having frozen. It now prints
  `range: 170 cm (61234 ms ago)`. New SDK accessor:
  `ultrawidelock_uwb_last_range_age_cm()`.
- **The 30 s session deadline is logged apart from the 5 s phase deadline,
  with the phase it hit.** Both used to read "credential phase deadline
  expired". A Watch whose Pre-POLL was accepted and that then never ranged
  is not a credential failure, and the next field log will say so.
- **Every ranging session leaves a one-line post-mortem.** At teardown the
  listener prints `I: ranging post-mortem: prepoll=N arm=N poll_ok=N
  poll_fail=N resp=N final=N range=N last_st=...`, the count of each step of
  the DS-TWR round, through the same printer as `Pre-POLL accepted`. Default
  on, printed off the critical path, no `uwbdiag` needed. SDK:
  `ccc_shim_rx_stats_get()`.

### Apple Watch, unlock on approach

Two faults, both measured on a DWM3001CDK on 2026-09-10 once the Watch's
key was trusted, both in the walk-away-and-come-back case that the Watch's
own ranging policy produces (it suspends ranging once far and restarts it,
same BLE session, once its wearer is back).

- **The reader dropped a live, ranging session at 30 s.** The connected cap
  was a hard age cap. The Watch's second approach in a session was ranging
  at 0 cm when the reader disconnected it for "session deadline expired",
  and it was back within a second, so the cap freed nothing. From
  ESTABLISHED on the cap is now an idle cap: every peer message and every
  accepted range refresh it. A peer quiet on both radios for 30 s is still
  dropped. SDK: `ultrawidelock_ranging_last_range_age_ms()`.
- **CDK: the second approach never unlocked.** A departure relock disarms
  the trajectory gate, which re-arms only on a range at or past
  `approach_cm`; the Watch restarts ranging already inside it (61 cm,
  130 cm measured). A ranging restart is now the same approach evidence a
  new session is, and arms the gate the same way. SDK:
  `ultrawidelock_uwb_start_generation()`.

### ESP32-S3

- **ESP32: the second approach never unlocked.** Same fault as the CDK's,
  same peer behaviour: the departure relock disarmed the trajectory gate and
  the Watch restarted ranging already inside `approach_cm`, so nothing
  re-armed it. The first approach worked because the far range does arrive
  there (no RSSI power gate); the restart-while-close case had nothing to
  arm on. The reader task now arms the gate on the two edges the CDK uses:
  a ranging restart (`ultrawidelock_uwb_start_generation()` moved) and a
  credential session coming up. A host test walks up, departs, restarts
  ranging at 130 cm and unlocks again; without the restart it stays locked.

### DWM3001CDK

- **`prov` can be typed at the RTT terminal.** The Matter image has no
  shell; `make monitor` feeds its `Terminal>` prompt into RTT down-buffer 0
  and the main loop drains it, the same line the ESP32 lock answers as
  `ultrawidelock prov`. Bench only. (A `trust` line that admitted whichever
  credential was presented last was here briefly for the Watch; the learn
  path above replaces it and took its flash.)

## [0.5.0] - 2026-09-09

The lock stops drawing current when nobody is at the door. The DW3110 never
slept in any earlier release; now it sleeps between sessions, and a battery
build puts the rest of the board down with it. This release also fixes six ways
the ESP32-S3 build failed to get a phone or a watch through authentication, all
of them present in v0.4.1.

### The DW3110 sleeps between sessions

`dwt_entersleep()` had zero call sites through v0.4.1, so the radio idled at
`IDLE_PLL` forever. It now goes down when the Pre-POLL listen stops and comes
back on the next approach. The datasheet's two states are **18 mA** idling
against **260 nA** asleep.

The wake is not inferred. It is a chip-select toggle, a confirmed `IDLE_RC`, and
a full config restore, and if the part does not answer its device id the radio is
rebuilt from reset rather than left half-awake. Walk-up unlock and the Home app
tile were both re-tested on hardware after every lever in this section.

### A battery build

`make build BATTERY=1` on the DWM3001CDK adds sleepy Thread, two-rate
advertising, and darkness. Register reads over SWD, before and after, no
estimates:

| | Before | After |
| --- | --- | --- |
| DW3110 | never slept | asleep between sessions |
| 802.15.4 receive duty | on in **20 of 20** samples | **0 of 20** |
| High-frequency crystal | up, always | down, 0 to 5% |
| BLE advertising | 30 to 60 ms, forever | 30 to 60 ms for 30 s, then 1.0 to 1.2 s |
| Board LEDs | heartbeat every 2 s while locked | dark while locked |

The default build keeps its lamps and its fast Thread. Nothing here is on unless
you ask for it.

### What that buys, and the one number that decides it

Adding up the terms this firmware controls: about **24.1 mA before, 0.060 mA
after**, roughly 400x. That total is PREDICTED from the two datasheets, not
measured with a meter, and the advertising and polling rows are the softest
figures in it.

The pivot is not firmware. A stock DWM3001CDK has a J-Link debugger and a power
LED on the same rail drawing something like 15 mA, and no Kconfig reaches them:

| Board | Before | After |
| --- | --- | --- |
| Stock CDK, debugger live | 3.7 days | 9.7 days |
| Custom board, or the debugger rail cut | 6.1 days | past six months |

Both rows assume a 5,000 mAh pack derated to 3,500 mAh usable. Treat them as two
hypotheses until a meter sits in series at the board's measurement header.
`docs/power-baseline.md` is the whole workbook, including what it still cannot
say.

### Fixes for anyone running v0.4.1 on ESP32-S3

Reported against a two-anchor ESP32-S3 build: an iPhone that froze after
Pre-POLL, and an Apple Watch that reconnected every 3 to 4 seconds and failed
authentication outright. Six defects, all shipped in v0.4.1:

- A single global connection-parameter retry, shared across connections, fired
  conflicting updates whenever a reconnect raced a stale link.
- A second phone finishing authentication was refused ranging instead of taking
  it over, which surfaced on the phone as a general error.
- The Pre-POLL stash was sized to the frame the lock expected rather than the
  127-byte maximum the radio can hand it, so a full-length frame was dropped.
- The signal-strength gate could hold the completion message past the phone's
  patience, which is about 1.9 seconds.
- Spare key generation overran its 3 KB stack and tripped the stack canary. The
  ESP32 build also never declared the option that sizes it, so setting it did
  nothing.
- The DW3110 woke for the first session after boot and no later one, which is
  the deep sleep above failing on its second use. It never shipped.

### Also in this release

- BLE advertising parameters were returned as a compound literal that went out of
  scope, so both parameter sets are now named and outlive the call.
- Documentation rewritten around what each feature does, with the walk-up
  recording moved under the layout.
- Host suites run **9,681 checks** across 18 suites, up from 9,608 at v0.4.0.

### Note for anyone building against the SDK

`VERSION` moves to the 0.5 series. While the SDK is pre-1.0 its generated CMake
package accepts only a matching minor series, so a consumer pinned to 0.4 has to
move with it. v0.4.1 shipped without bumping this file, so images from that tag
carry a 0.4.0 version in their MCUboot header.

Full diff: <https://github.com/ultrawidelock/ultrawidelock/compare/v0.4.1...v0.5.0>

## [0.4.0] - 2026-08-28

The lock stopped needing Zephyr, grew a second anchor so it can tell inside from
outside, and learned to take a firmware update from a browser. 599 commits and
30 pull requests since v0.3.0, across 2,947 files.

### Read this before you update a v0.3.0 board

**Existing pairings do not survive.** The DWM3001CDK settings partition moves
from `0x7e000` to `0x7c000` and the custom Matter record schema becomes `mf2`.
Matter fabrics and the Home Key reader identity are deliberately not migrated:
Apple Home has to add the lock again, and Home Assistant has to be shared again
after that. This is a one-time break, and the partition does not move again.

If you want the old identity off the part first, back it up over SWD before you
flash. `ultrawidelock export` will not do it, because the Matter image compiles
no shell:

```sh
JLinkExe -device nRF52833_xxAA -if SWD -speed 4000 -autoconnect 1 \
  -CommanderScript <(printf 'savebin s.bin 0x7C000 0x4000\nexit\n')
```

Check the result is 16,384 bytes and not all `0xFF` before you trust it. An
erased page saves silently and looks exactly like a backup.

### A third port, and no Zephyr in it

The same lock now builds on **FreeRTOS on the nRF52833**, assembled a layer at a
time and measured as each one landed: NimBLE on the SoftDevice Controller with
MPSL arbitrating flash against the radio, OpenThread on the pinned 802.15.4
driver, Mbed TLS and PSA, the DW3110 over SPIM3, a persistent key-value store,
and the Matter node on a checked shim. The provisioning console runs over USB
CDC ACM and no longer needs SW2 held to reach it.

Signed updates over BLE work on this port, on the oracle's wire protocol, and
have been proven on hardware.

### Two anchors, and a side to be on

A second anchor turns one distance into a side. The satellite ships as a
standalone app on both the ESP32 tier (over an ESP-NOW carrier) and the CDK, it
reports its distance sealed and bound to the ranging block it came from, and the
lock fuses the pair only when both halves come from one block.

- **The side gate fails closed** for passive unlock: no agreeing second opinion,
  no walk-up open. `docs/bench-inside-outside.md` runs the three-board bench.
- **Inside and outside BLE witnesses**, with a proven pick that outlives the
  approach and follows BLE address rotation.
- A lock-owned freshness epoch, so a reboot cannot roll the replay window back.
- Per-board UWB range bias calibration, and a configurable OUTSIDE margin.

### Updates from a browser, on either chip

**[ultrawidelock.com/flash](https://ultrawidelock.com/flash/index.html)** finds
the board, reads what it is running, and sends the one update that applies.
Chrome or Edge on a computer, or Chrome on Android. Neither Web Bluetooth nor
WebSerial exists in Safari, so not from an iPhone.

|  | DWM3001CDK | ESP32-S3 / C5 / C6 |
|---|---|---|
| Transport | mcumgr, over BLE **or** USB | native GATT frames |
| Payload | signed delta, about 11 KB | signed whole image, about 2 MB |
| Time | seconds | several minutes over BLE |

Nothing is written until you open the update window on the board itself: **SW2**
on the CDK, a **double-click** on the ESP32 button. Authenticity is a P-256
signature checked before a byte is written and again by the bootloader.

The CDK also gained **reinstall over the cable**, which is the one that matters
when things have gone wrong: a whole signed image through MCUboot serial
recovery, needing no starting image, no update window, and no working software
on the board.

Hardware status: the browser delivered a delta to a real board over Web
Bluetooth on 2026-08-27 (CDK-30), and serial recovery itself is proven
(CDK-16). The no-delta-applies path (CDK-31) and the cable-versus-radio timing
(CDK-33) have never been run against hardware.

### Matter Door Lock grew up

- `LockOperation` events, `AutoRelockTime`, and both writable Door Lock
  attributes persisted across reboot.
- Apple's **Approach Direction** cluster, and a live **UWB presence** cluster
  that reads only with the Manage privilege.
- **`DoorLockAlarm`**, so the lock can report the door and not just the bolt: a
  forced door from the impact latch, a door left ajar from the swing angle.
  Anchor builds only, and no controller has been seen rendering one yet.
- **A Matter client**, so a walk-up here can open a *second* Matter lock with no
  hub automation in the path: CASE as initiator, the Binding cluster, and a
  `chip-tool` helper that sets up both ends. Off by default. Working on hardware
  since 2026-08-22 against a second lock built from this repo; no commercial
  lock has answered it yet.
- Multi-admin commissioning hardened: five-fabric Apple Home plus Home Assistant
  coexistence on the CDK, one committed Thread dataset, provisional
  commissioning rollback, selective durable `RemoveFabric`, per-fabric state,
  and transactional retries.
- The UWB device id is now derived from the credential, and identifier hashing
  left the hot path.

### Home Assistant

A companion integration, with persistent UWB policy controls and independent
lock action policies, so presence can drive one thing and unlocking another.

### Portability, and gates that keep it

- A **key-value seam addressed by number, not by name**, implemented over Zephyr
  settings, ESP-IDF NVS and the FreeRTOS store, with storage names declared once
  and gated against drift.
- A datagram seam for the sealed link, and AES-128-CCM in the crypto primitive
  seam.
- **`make sdk-export`** for the hardware-agnostic SDK, plus a size gate on every
  port and a port purity gate that now covers the whole tree rather than 64% of
  it.
- CI compiles firmware on every change that can break it: the CDK client image,
  the anchorlink image, the shipping image and the satellite, taking application
  coverage to 9 of 13.
- Static analysis gates for the portable tree, and workspaces shared by content
  hash so a build does not rebuild eleven patches to find out nothing moved.

Host suites now run **9,608 checks** across 18 suites, up from 7,979 at v0.3.0.

### Fixes worth naming

- Matter: resend Sigma3 for a duplicate Sigma2, republish the SRP name after a
  re-pair, chunk large NOC lists, and report operating modes right-side up.
- Credential: hold the bolt through an iOS session flap, relock on a graceful
  close, and meet PSA's output-size contract on the multipart AEAD path.
- Report lock-state truth to Matter even when the phone is gone.
- ESP32: the provisioning namespace fits in NVS again, and four ways the ESP32
  two-anchor gate diverged from the nRF lock are closed.
- Latch: a reboot no longer freezes the entry dwell, and a settings load no
  longer resets the tuning.

Full diff: <https://github.com/ultrawidelock/ultrawidelock/compare/v0.3.0...v0.4.0>

## [0.3.0] - 2026-08-05

Released before this file existed. See the
[v0.3.0 release notes](https://github.com/ultrawidelock/ultrawidelock/releases/tag/v0.3.0).

## [0.2.0] - 2026-07-22

Released before this file existed, under the project's former name.

## [0.1.0] - 2026-07-22

First tagged release, under the project's former name.
