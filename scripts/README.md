# Scripts

Command-line helpers behind the Make targets. Prefer the target when one exists;
`make help` lists the supported interface. Use `make hitl` for `hitl-run.sh`,
passing its flags through `HITL_ARGS`.

| Group | Scripts |
|---|---|
| Setup and environment | `bootstrap.sh`, `esp-bootstrap.sh`, `toolchain.sh`, `check-signing-key.sh`, `check-approtect.sh`, `ws-link.sh`, `ws-store.sh` |
| nRF5340 DK builds | `nrf5340dk-build.sh`, `app-upstream-diff.sh`, `integration-patch-id.py` |
| DWM3001CDK operations | `cdk-dfu.sh`, `cdk-find-probe.sh`, `cdk-rtt-elf-check.sh`, `mcuboot-keyhash-check.py` |
| FreeRTOS port checks | `freertos-platform-check.sh`, `freertos-radio-source-check.sh`, `freertos-ble-source-check.sh`, `freertos-crypto-source-check.sh`, `freertos-matter-source-check.sh`, `freertos-ncs-source-check.sh`, `freertos-vector-check.sh`, `freertos-printf-check.sh`, `freertos-hal-fake-fidelity.py`, `freertos-ble-liveness.py`, `freertos-pairing-code.py` |
| Firmware size | `cdk-size.py`, `cdk-size-compare.py`, `cdk-size-baseline.py` |
| Stack depth | `cdk-stack-depth.py` |
| Delta update and SMP | `ultrawidelock_patch.py`, `ultrawidelock_push.py`, `ultrawidelock_smp.py`, `ota-index.py` |
| Provisioning | `ultrawidelock-enroll.py`, `spake2p_verifier.py`, `bind-helper.py` |
| Release and validation | `release-bundle.sh`, `release-notes.sh`, `sdk-export.sh`, `hitl-run.sh`, `regress-hil.sh`, `test-runner.sh` |
| Shared shell library | `lib/ui.sh`, `lib/setup.sh`, `lib/ws.sh` |

## The shared library

`lib/ui.sh` is sourced, not run: the progress display behind Make targets that
take minutes. On a terminal it draws a step counter, percentage, bar and elapsed
time; in a pipe, a file or CI it prints one line per step and no escape sequences.
The wrapped command's output is untouched either way. `ULTRAWIDELOCK_UI=0` forces
the plain form, `1` the drawn one, and `scripts/lib/ui.sh --self-test` checks it
against a terminal missing colour, UTF-8, width or `$TERM`.

`bootstrap.sh` (NCS) and `esp-bootstrap.sh` (ESP-IDF and esp-matter) both source
`lib/setup.sh`, which owns the phase output, the `die` format, the traps that keep
an interrupt legible and a `set -e` abort nonzero, `ask`/`SETUP_AUTO`, the per-host
package hints and the disk and network checks.

## Workspaces

`ws-link.sh` points a checkout at the workspace its branch needs. The machine
keeps one store (`lib/ws.sh`), a tree per pin and patch set: a checkout that
agrees with one already there is a symlink, and a branch carrying its own patch
set gets a copy-on-write clone of the nearest entry and a re-patch, not a
re-fetch. `make ws-link` links the checkout it runs in; pass a path to link
another, which is how to reach a worktree whose branch predates the script.
`make ws-store` lists what the machine holds and which checkouts still link to
it.

`ws-link.sh --print` names the entry a checkout resolves to and changes nothing.
The name is a function of the pin, the NCS version and the patch files, so it needs
no workspace, toolchain or network. That makes it the cache key for a build runner:
restore the store entry under that name, `make ws-link`, and a build that would have
refetched for an hour starts immediately. Restoring by the fetch-key prefix alone is
also safe: the restored tree keeps its own name, and `ws-link` clones and re-patches
it into the right one.

`app-upstream-diff.sh` says how our copy of the door-lock application differs
from Nordic's, by fetching just that path at the pin and diffing. It reports
rather than gates. Read it before raising `PIN`.

## Updates over BLE and SMP

The native BLE delta-update protocol is version 2. Every request carries a
nonzero transfer ID, DATA also carries its absolute offset, and each successful
reply echoes the transfer ID plus the receiver's next offset, so retrying an
unchanged frame after a lost notification is safe. Version-2 request opcodes are
`0x11` through `0x14` and do not overlap the old transfer-blind protocol, so a
mixed host and firmware pair fails loudly.

**Error 8**, "another update transport owns the receiver", means the SMP half or
an earlier BLE session still holds the claim. It clears on disconnect or when the
update window closes. It is not a signature or corruption failure.

`cdk-dfu.sh` takes one operator step: a **>= 5 s SW2 hold while the application
is running**, which requests MCUboot serial recovery and warm-reboots into it. Its
fourth argument, the chip name, is vestigial.

`ultrawidelock_smp.py --serial PORT` speaks the same mcumgr conversation down
`uart0` instead of over the radio. Everything above the transport is one code
path.

```sh
make ota-smp-list OTA_SERIAL=auto        # what is the board running?
make ota-smp      OTA_SERIAL=auto        # push the delta down the cable
```

`auto` picks the first `/dev/cu.usbmodem*`; name a port when more than one probe
is attached. On the DWM3001CDK that port is the **J-Link OB's VCOM**, not the
second USB socket: the probe owns `uart0` and the application talks down it,
while the second socket goes to the nRF52833's own USB and is inert outside
provisioning mode.

Two things answer on that one port, and the client cannot tell them apart by
asking:

| | answers when | takes | chunk |
|---|---|---|---|
| the application | it is running, and `SMP=1` | a signed delta | `--chunk 384` (default) |
| MCUboot | after a >= 5 s SW2 hold, or when no valid image exists | a **whole** signed image | `--chunk 128` |

MCUboot's is the only path on this board needing no starting image, which is what
lets it rescue a board whose application does not boot. `ultrawidelock_smp.py
--serial` is proven against it: entered over SWD with `make ota-recovery` on
2026-08-27, MCUboot accepted a full 406,524 B image and the board booted it.
[CDK-16](../docs/hardware-validation.md) now covers only the SW2 entry and the Go
`mcumgr` client.
