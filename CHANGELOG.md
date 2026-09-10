# Changelog

What changed for someone running the firmware, not the commits that got it
there. `scripts/release-notes.sh` reads the section matching a tag and renders
it into that release's notes, so this file is the authored source and the git
log is only the fallback.

Versions follow [semantic versioning](https://semver.org). Dates are the day the
tag was cut.

## [Unreleased]

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
