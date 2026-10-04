# Troubleshooting

Common issues, grouped by target. Protocol background is in
[`protocol-research.md`](protocol-research.md) (on-air behavior) and
[`protocol-notes.md`](protocol-notes.md) (firmware time and credential behavior).

| Section | Target |
|---|---|
| [DWM3001CDK](#dwm3001cdk) | the primary board, one nRF52833 with the DW3110 beside it |
| [Build and flash](#build-and-flash-nrf5340-dk), [Hardware](#hardware-nrf5340-dk-and-dwm3000evb) | nRF5340 DK, the target with NFC |
| [ESP32-S3 ports](#esp32-s3-ports) | ESP32, and then the much longer [gotchas log](esp32-gotchas.md) |
| [Unlock behavior](#unlock-behavior) | any target: this is protocol, not board |
| [Tests and CI gates](#tests-and-ci-gates) | the host sweep, no hardware involved |

Bare make targets mean the DWM3001CDK. The nRF5340 DK is `nrf-` prefixed and the
ESP32 is `esp-` prefixed; `make` with no target prints the grouped list.

## DWM3001CDK

Full detail is in [`../apps/dwm3001cdk-lock/README.md`](../apps/dwm3001cdk-lock/README.md);
bring-up traps are in [`dwm3001cdk-surgery.md`](dwm3001cdk-surgery.md).

**`make build` fails at configure, complaining about a signing key.** Run
`make dfu-key` once. Every image on this board is signed, the key is gitignored,
and a fresh clone or worktree has none; the build refuses rather than fall back
to the demo key published in MCUboot's own repository. `make nrf-build` stops the
same way, same fix, under its default `DFU=1`.

**`make monitor` attaches cleanly and prints nothing.** probe-rs reads the RTT
control block address from the ELF you pass it, so an ELF built but not flashed
gives a stale address and looks like a dead board. Reflash, or point
`CDK_RTT_BUILD` at the image the board is running.

**A log line looks wrong, or mentions something the code cannot do.** probe-rs
prints tails of `.rodata` strings from the ELF, so a phantom line can appear with
no target attached. A real line has an `HH:MM:SS.mmm:` prefix, a complete
sentence, and its `%d` and `%s` substituted.

**The probe enumerates but nothing can connect to it.** A stale process holds the
USB interface after an interrupted `west flash` or a SIGTERMed `probe-rs attach`.
Replugging works but needs a human; killing the holders does not:

```bash
pkill -f 'jlinkarm_nrf_worker_osx'
pkill -f 'JLinkGUIServerExe'
```

A `make flash` reporting "Timed out waiting for response from worker" after
"Verifying image" has usually programmed correctly and failed only on the reset.
Check with a read before reflashing.

**Apple Home sits on "Adding to Home" and never finishes.** On a factory-erased
board, old images could lose the OpenThread SRP client key while the border
router kept its name lease. The current image persists the SRP key and name
identity together, keeps asynchronous removal objects alive until OpenThread
returns them, and retries a duplicate service name. Capture the RTT log first; a
border-router restart is a fallback, not the repair.

**Apple Home works, but Home Assistant loses the lock after sharing it.** Usually
two Thread networks, not a Matter fabric problem. In the Home Assistant iOS
Companion app, open **Settings > Devices & services > Thread > Configure**, send
the Apple credentials, refresh, and make that network preferred. Join Home
Assistant's OTBR to those credentials rather than commissioning the lock onto a
second dataset, then share the Apple accessory again. See the
[DWM3001CDK multi-admin guide](../apps/dwm3001cdk-lock/README.md#apple-home-plus-home-assistant).

**A Home Assistant sharing attempt failed.** Let the fail-safe expire before
retrying. New fabrics are provisional and only the failed attempt rolls back, so
Apple Home is undisturbed and no persistent slot is consumed. If the new
controller already reached `CommissioningComplete`, remove that fabric from a
surviving controller with **Manage fabrics**.

**Apple Home removed the lock on its own after a reset or a reflash.** The log
shows `cluster 0x0101 command 0x001b` and then `cluster 0x003e command 0x000a`:
`GetUser`, then `RemoveFabric`. Read the `->` line under each. `-> user N in use
0` means the hub did not find the user it wrote at setup, which firmware older
than the stored user table answered after every restart. `-> fabric A removed by
fabric B` names the administrator that went, and A equal to B is a controller
removing itself. The other fabric is still on the lock, so it does
not advertise for pairing: share it again from the controller that is left, or
hold SW2 through reset and pair from the start. A lock paired before that
firmware has no stored table and needs this once more.

**The lock reports a full fabric table.** Five committed fabrics are supported;
Apple Home commonly accounts for two and Home Assistant one. Remove an unused
controller through **Manage fabrics**: authenticated `RemoveFabric` tombstones
only the target, revokes its sessions, ACL, subscriptions and SRP service, and
keeps the others live. Use SW2 only if no administrator can reach the lock.

**The lock works but the phone never approaches it.** The reader advertises its
Aliro service with the provisioned advertising parameters only once it has an
identity, and on the Matter image that identity is minted by commissioning.
`make flash-erase` takes the fabrics, identity and trust anchors with it, so the
board must be added to Home again. To clear one controller, use its authenticated
fabric-management UI; **SW2 through reset** clears every Matter and Home Key
identity, the last-resort recovery.

**The board refuses an over-the-air patch.** A delta is computed against the
exact bytes the board is running, and only the build host keeps that record. A
push from a phone is invisible to it: run `make fota-done` after every one.

**Nothing happens when you press SW2 during an update.** D10, the blue LED,
blinks at 2 Hz while the update window is open. It follows the window, not the
button, so it goes out when the five minutes expire on their own. A dark LED means
no window, not a failed transfer.

**The board rebooted while SW2 was held.** SW2 has two meanings, separated by
hold time:

| Gesture | Effect |
|---|---|
| Short press | Opens the application update window (the 2 Hz D10 blink above) |
| Hold >= 5 s **while the application runs** | Requests MCUboot serial recovery and warm-reboots into the bootloader |

The boot banner prints `hold SW2 for 5000 ms to enter MCUboot recovery`; the
duration is `CONFIG_ULTRAWIDELOCK_MCUBOOT_RECOVERY_HOLD_MS`. The old 5 s mcumgr
wait at every boot is gone (`CONFIG_BOOT_SERIAL_WAIT_FOR_DFU=n`), so there is no
window to catch with an SWD reset. `scripts/cdk-dfu.sh` depends on the hold and
no longer resets over SWD.

**The image does not fit.** The Matter image is at **96.3% of its flash partition**
(417,684 B of 433,664 B, about 15.6 KB spare) and 90.3% of RAM (118,312 B, about
12.8 KB spare). **Flash is the tighter of the two**, so a new code path is a bigger
decision than a new static allocation. LTO is on by default and worth 41,084 B;
`LTO=0` no longer fits this flash map and the build says so.

**Do not compare against a size baseline taken before the project rename.**
`make cdk-size-check` refuses, correctly: a number measured across a
configuration change is worse than no number. Refresh with
`make cdk-size-baseline` rather than widening a cap.

## Build and flash (nRF5340 DK)

**`make nrf-build` stops before it starts, saying it will not build a bootloader
anybody can sign for.** Run `make dfu-key` once per clone. `DFU=1` is the default
here, and with no key configured MCUboot falls back to the one published in its
own repository, which every stock MCUboot trusts. `DFU=0` builds the older
no-bootloader bench layout and needs no key.

**`make nrf-build` can't find the toolchain.** `make bootstrap` installs the NCS v3.3.0
toolchain, so this normally means bootstrap has not been run here (`make tools` says
whether it is installed). All builds go through `nrfutil sdk-manager toolchain launch …
west`. For a toolchain managed some other way, `nrfutil sdk-manager config show` names the
directory bootstrap looks in, and `ULTRAWIDELOCK_TOOLCHAIN=env` uses whatever is on
`PATH`.

**`make bootstrap` says nrfutil is not on PATH.** It installs the toolchain, so bootstrap
stops in preflight rather than after the 6.5 GB fetch. On macOS and Linux it offers to
install it: one 5 MB binary from Nordic into `~/.local/bin`, `y` to accept.
`SETUP_AUTO=1 make bootstrap` accepts without asking (CI and containers), `SETUP_AUTO=0`
never asks. Otherwise, or on another platform,
[download it from Nordic](https://www.nordicsemi.com/Products/Development-tools/nrf-util).

**`nrfutil` is installed but `make bootstrap` still fails on `sdk-manager`.** nrfutil is a
launcher that ships with no commands inside it. Bootstrap adds the manager
(`nrfutil install sdk-manager`, a few seconds) when missing; run that by hand if you drive
nrfutil directly. `make tools` lists `nrfutil`, `sdk-manager` and `toolchain` as three
separate rows for this reason.

**`make bootstrap` stops in preflight over disk, or a missing `git`/`curl`/`python3`.** It
reports every gap in one pass with the install command for this host, because the later
phases cost several GB and many minutes. For disk, `ULTRAWIDELOCK_WS_STORE=/big/disk/ws
make bootstrap` moves the workspace store to another volume, and in a second checkout
`make ws-link` links the tree the machine already has.

**`make bootstrap` was interrupted.** Re-run it. Every phase resumes: the toolchain install
is skipped once installed, a half-finished clone is repaired and re-pinned, the fetch
sentinel keeps `west update` from starting over, and the patches are reset and reapplied.

**A config change flashed but did not take effect.** A change to net-core configuration
needs a full erase: use `make nrf-flash-erase`, not `make nrf-flash`, which is app-core
only and leaves the net-core image in place.

**`make nrf-term` shows nothing.** The console and Zephyr shell are on the DK's VCOM1; VCOM0
is silent. `make nrf-term` auto-detects VCOM1; override with `PORT=` if detection
picks the wrong port.

**Build succeeds but the image does not fit.** The default configuration targets a full
flash budget (app FLASH is ~89.7%). Extra features may need a config trim; build with
`PRETTY=1` for readable size output.

## Unlock behavior

**This lock does not open the lock it is bound to.** That path is off unless the
firmware was built with `CLIENT=1`. It has worked on hardware since 2026-08-22
against a second lock built from this repo; no commercial lock has answered it.
`docs/matter-binding-bench.md` is the bring-up procedure: what to prove before
blaming the client, which log line to read, and which two failures are known
deviations.

**Check tap first.** Tap exercises the BLE transport, provisioning, and
credentials. If tap works and only approach fails, the fault is UWB-specific, not
in the credential path.

**Tap works, approach never ranges.** Either no common protocol version was negotiated, or
the reader never emitted the `0x98` "URSK ready" trigger, so the phone reports
`URSK_Unavailable`. See [`protocol-research.md`](protocol-research.md) §4 and §10's guide.

**Approach worked, then stopped after a reboot.** The time/credential-validity path, not
UWB. The RAM wall clock is erased on reset and falls back to a stale Last Known Good Time,
so freshly minted Access Documents are rejected as not-yet-valid. See
[`protocol-notes.md`](protocol-notes.md); this repo carries the ratchet and persist fixes.

**Approach stopped but tap and Matter still work, no reboot involved.** If the clock is
valid but behind real time by more than the advertisement window (default 900 s), phones
ignore the BLE advertisement because its dynamic-tag expiry lies in their past. See
[`protocol-notes.md`](protocol-notes.md); the board overlay disables the tag until a real
time source exists.

**Ranging dies after walking out of range, or after about 12 hours.** Expected: the URSK
has a 12-hour TTL and is dropped when the BLE link drops. A fresh access transaction, via
the fast path, re-arms it. See [`protocol-research.md`](protocol-research.md) §8.

**Setup (M1-M4) completes but there are zero distance reports.** A radio-path or
parameter problem, not a control-stack one: check the antenna and channel (5 or 9),
confirm a time sync happened (wrong listen window otherwise), and check for a negotiated
parameter mismatch, which yields a different SaltedHash and so a different STS with no
shared frames. See [`protocol-research.md`](protocol-research.md) §6-§7.

## Hardware (nRF5340 DK and DWM3000EVB)

None of this applies to the DWM3001CDK, where the DW3110 sits on the same module
as the MCU and the wiring is internal. Its pin table is in
[`../apps/dwm3001cdk-lock/README.md`](../apps/dwm3001cdk-lock/README.md).

Pin assignments in
[`apps/nrf5340dk-lock/overlays/dw3000-nfc.overlay`](../apps/nrf5340dk-lock/overlays/dw3000-nfc.overlay)
are the source of truth. If the overlay changes, the wiring must change with it.

**The DW3000 is a 3.3 V part.** Power the DWM3000EVB from a 3.3 V rail, not 5 V. Share a
common ground with the host board.

**No SPI response / DW3000 not detected.** Confirm the EVB is powered, the SPI lines match
the overlay, and the reset and IRQ lines are wired. `make nrf-selftest` builds a boot
self-test with no phone present, isolating a wiring problem from a protocol one.

**The DWM3000EVB has its own power-select jumper.** Correct rails are not enough if that
jumper selects the wrong source: SPI then fails silently, with no valid device ID and a
responder that never listens. Check it before suspecting software.

## ESP32-S3 ports

Full detail is in [`docs/esp32-gotchas.md`](esp32-gotchas.md).

**`ESP-IDF export.sh not found` or `esp-matter not found`.** Nothing is installed at the
path the build looks in. `make esp-bootstrap APP=reader` installs ESP-IDF alone (about
5 GB, enough for the reader, satellite and initiator apps); `make esp-bootstrap` also
installs esp-matter, which `APP=matter-lock` needs, for about 15 GB more and nearly an
hour. Both stages ask first, `SETUP_AUTO=1` accepts without asking, and an existing
install is reached with `IDF_EXPORT=` and `ESP_MATTER_PATH=`.

**`make esp-bootstrap` stopped partway through esp-matter.** Re-run it. The clone is
pinned and reused, and the install repeats only when its marker
(`.ultrawidelock-install-done` in the esp-matter tree) does not match the revision being
installed. If the tree itself is the problem, `rm -rf` it and re-run.

**`make esp-bootstrap` installed a different version than the bench uses.** It defaults to
ESP-IDF v5.5.4 and esp-matter `93b1680` only when it starts from nothing; an existing
checkout is offered a re-pin and keeps whatever you choose. `IDF_VER=` and
`ESP_MATTER_REV=` (a full 40-character SHA) choose others, and the build enforces neither.

**`dwt_probe failed: -1` the first time a phone reaches M4.** The DW3000 was never
brought up at boot, so the first SPI touch happens inside a NimBLE host callback, where
the shallow stack and missing init make probing fail. Bring the radio up once from a
dedicated startup task; both ports now do this.

**The bolt moves but the Wallet never animates.** Driving the lock is not the signal iOS
watches: the reader must send the Reader-Status-Changed grant message over the BleSK
channel, and without it iOS shows only a plain Matter accessory notification. Neither the
phone's computed distance nor the advertisement tag is the gate.

**The phone disconnects about 1.8 s after a successful EXCHANGE (reason 531).** The
reader did not send Reader-Status-Access-Protocol-Completed, which is mandatory.

**`GeneralError URSK_Unavailable` at M1.** The ranging session id is derived from the
AUTH0 transaction id, not chosen by the reader. A hardcoded session id names a session
the phone has no key for. This is never a wrong-URSK-value problem: M1 carries no
URSK-derived material, so a value mismatch would surface later, at M2-M4 STS.

**`protocol 0 unsupported` fed to the ranging engine.** Ranging SDUs ride their own GCM
channel keyed from BleSK, with fresh per-direction counters, not the credential-auth
channel. Seeing the raw envelope type as a protocol number means the split was missed.

**Ranging setup completes, POLL and Response look clean, but no distance is ever
computed.** On ESP32 this is usually a real-time fault, not a logic fault: a per-round
blocking log in a path with a 2 ms deadline starves the DW3000 ISR task, so the Final
callback dispatches too late to catch the phone's Final_Data. Throttle hot-path logging
first, then look at SPI transaction cost.

**Negative or absurd distances.** Suspect cross-round timestamp mixing before antenna
calibration. If one round's Final_Data is decoded after the next round has overwritten
the shared timestamps, the arithmetic produces plausible-looking but wrong values that
still pass the integrity gate. Snapshot the intervals at Final capture. No antenna
calibration was needed on this hardware.

**Approach unlock works, then the bolt relocks 5 s later while the phone is still
there.** A fixed auto-relock timer fights approach unlock. Set `AutoRelockTime = 0` and
drive relock from proximity with hysteresis.

## Tests and CI gates

**`make check` says a gate COULD NOT RUN and exits nonzero.** Deliberate, not a warning:
the gate's tool is not installed, and CI will run it whatever this machine has, so "could
not check" reads as "not verified". `make tools` fills the gap. To accept it for one run,
scope it out by name: `SKIP="cbmc docs" make check`.

**A gate passed here and failed on the PR.** Two usual causes: a version-pinned tool
(`clang-format`, `clang-tidy`, `zizmor`, `reuse`) off CI's pin, which `make tools` flags;
or a gate that ran weaker here, since without the `markdown` python package the flash-HTML
drift check skips, which `make tools` also reports.

**`make check` is slow, or a failure is hard to read.** It runs in parallel lanes, so rows
arrive out of order and two lanes can fail in one sweep. `SERIAL=1 make check` runs one
gate at a time in table order; to re-run a single gate, scope the rest out with `SKIP=`.

**A host suite reported green over code that does not compile.** Only on trees before
`396fee04`. A parallel stage was invoked as `"$fn" || rc=$?`, and bash suppresses
`errexit` inside a condition context, so a stage whose compile failed ran the *previous*
binary. Each stage now runs in its own `(set -e; ...)` subshell and `wait` carries its
real status. On an older tree, remove the build directory and re-run.

**`git pr` cannot run network, Emscripten, user-local tools, or `.venv` gates.** Its
disposable candidate deliberately has no network, real home directory, user-local `PATH`,
or gitignored files. Configure `git config git-pr.verify make check`; the wrapper runs the
hermetic candidate checks and leaves the unavailable seven to CI. Do not configure
`make check` directly for that sandbox: it is the full developer sweep and treats those
missing capabilities as failures.

**`python3 web/build.py` refuses to run.** It stops when `HEAD` is behind `origin/main`,
because regenerating from a stale tree writes stale pages. `git fetch origin && git merge
origin/main` first.

## Still stuck

Open an issue with the firmware commit, target, and console log; see the bug report
template. For security-sensitive reports, use private reporting
([`../SECURITY.md`](../SECURITY.md)).
