# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

**Primary: Apple ecosystem and UWB tinkerers who want a working lock.** They
arrive without an embedded toolchain and usually without the reference board.
Success is reaching something real from the browser alone: flashing an ESP32
over WebSerial, or walking a phantom phone at the lock in the digital twin.
Confirmed by the user during init.

Two audiences are visible in the repository but were not confirmed as targets:
engineers porting the firmware to another board (`PORTING.md`, the five HAL
seams) and readers auditing the distance bounding claim. Treat them as present,
not as the people the surfaces are optimized for.

## Product Purpose

UltraWideLock is portable firmware for NFC and UWB smart locks. It
implements Aliro, the CSA's door-lock credential standard, on real hardware
across BLE, NFC over ECP, and UWB ranging, with three complete locks plus
reader, initiator and anchor examples.

`web/` is the project's public face and its no hardware on ramp. It carries four
surfaces: the site (landing page plus 18 guides rendered from `docs/*.md`), a
WebSerial flasher, a digital twin running the ranging stack compiled to WASM,
and a subsystem graph. Success for the site is a visitor who understands the
measurement and then does something with it without owning the board.

## Positioning

The lock measures the distance instead of trusting it. Range comes from time of
flight under a rotating STS session, so a relay can add delay and nothing else,
which moves the measurement away from the door rather than toward it. Three
facts a neighboring project could not truthfully copy:

1. The whole stack runs on one nRF52833: reader, DW3110 radio, OpenThread MTD,
   and a Matter node written by hand rather than built on CHIP, which is what
   makes it fit.
2. Verification happens on the lock. No app, no account, no cloud round trip,
   and therefore no remote verifier to compromise.
3. The digital twin runs the firmware's own ranging logic compiled to WASM, not
   a re-implementation of it in JavaScript.

## Operating Context

- Evaluation starts at a terminal or a browser, not at a store page. The
  repository's own quick start is `git clone`, then `make check`, which needs
  only a C compiler and `python3`.
- The default board is the Qorvo DWM3001CDK (nRF52833 plus DW3110 plus J-Link on
  one part, nothing to wire). Other targets are the nRF5340 DK with DWM3000EVB
  and NFC12A1, and ESP32-S3 / C5 / C6 with DWM3000EVB.
- The console is RTT, not UART. `make flash-erase` costs every Matter fabric
  and the Home Key commissioning. These are bench defaults and the project
  says so.
- The flasher needs a WebSerial capable browser and a USB connected ESP32. The
  twin needs the WASM bundle, which is built from `web/twin/twin_glue.c` when
  emscripten is present; when it is absent the page says so plainly.
- The site is served either from a domain root or from a project subpath. Links
  are relative and their depth is computed per page so both work unchanged.

## Capabilities and Constraints

**Hard functional constraint, stated by the user during init:** the logic behind
the digital twin and the flasher must not be deleted or broken by design work.

Build and structure:

- `python3 web/build.py --check` builds `web/dist/` and fails on any dead link.
  Stdlib Python only. No node, no bundler, nothing to install.
- Nothing generated is committed. `web/dist/` is gitignored and disposable; the
  fix for a stale site is to build it again. `twin.js` is never committed.
- Nothing outside the repository. A fresh clone must build the whole site.
- Every page's `<head>`, topbar and footer come from `build.py` through the
  markers `@@HEAD@@`, `@@NAV@@`, `@@TOOLBAR:crumb@@`, `@@FOOTER@@` and
  `@@SITEJS@@`, not from the page source.
- CSS source files are split for authoring and concatenated into a single
  `styles.css` at build time. Do not add an `@import` between them.

Gates that fail `--check`:

| Gate | Checks |
|---|---|
| link gate | every relative `href`/`src` in the output resolves |
| `web/twin/check_constants.py` | the twin's `FW` table still matches the C it cites |
| `web/site/check_hero_constants.py` | the landing hero's tick rate and unlock bound |
| `web/flasher/check_codes.py` | the setup code, QR payload and its provenance hash |

The two constant gates share the convention `NAME: value, // path:line`. The
format is load bearing: a gate re-reads each cited line and fails if the value
moved off it. Do not reformat those tables.

Graph data:

- `web/graph/files.json` (680 KB, committed) yields the 3D file level graph,
  393 files and 703 links. `web/graph/subsystems.json` (4 KB, committed) yields
  the flat SVG graph, 17 subsystems and 49 edges. Both are reductions of
  `graphify-out/graph.json` (11 MB, not committed, 7,969 nodes and 18,457
  edges, produced by a tool that is not in this repository).
- Both committed files are refreshed together by `make docs-graph-refresh`,
  never as a side effect of a build. The 4 KB one records the commit it was
  extracted at, so a build that rewrote it dirtied every worktree and
  conflicted on that line between branches.
- The 3D page is the default, including in CI. It falls back to the flat SVG
  when `web/vendor/3d-force-graph.min.js` is absent, which is a fallback and
  not a degraded mode: the flat page is always correct. The Graph nav link is
  emitted only when the graph was actually built.

Network surface:

- Fonts are self-hosted WOFF2. The one external subresource on the whole site is
  `esp-web-tools` on the flasher page, pinned to an exact version with an SRI
  hash and constrained by that page's CSP.
- Canonical origin is `https://ultrawidelock.com` (`web/build.py:68`), with a
  generated `robots.txt` and `sitemap.xml`.

Content truth the surfaces encode:

- The shipped classifier separates a direct first path from a late, spread,
  obstructed one. The site carries that as a two signal vocabulary
  (`--path-first`, `--path-late`) meaning the same thing on the landing hero, in
  the twin and in the guides. One meaning per signal is product truth. The
  specific colors are not pinned (see Brand Commitments).

## Brand Commitments

- Name: **UltraWideLock**. Current version line v0.4.0. License is ISC; the
  vendored Qorvo UWB driver is LicenseRef-QORVO-2, so binaries built with UWB
  support inherit a Qorvo hardware restriction.
- **Design system ownership changed during init.** `web/assets/design/` was
  vendored from the UltraWideLock v2 design system with token and class names
  kept identical so it could be re-vendored by copying files over. The user
  ended that: this repository now owns the design system outright, and tokens,
  classes and visuals may change here without upstream coordination.
  `web/README.md` lines 112 to 117 still describe the old vendoring rule and are
  stale on that point.
- **No aesthetic constraint was pinned.** The typeface pair, the dark canonical
  with an AA light theme, and the no third party build rule were each offered as
  binding commitments during init. The user declined to pin any of them and
  asked instead that the site and all its components be made extremely polished,
  subject only to the twin and flasher constraint above.

## Evidence on Hand

Real captures, all in `assets/`:

- `hero.gif`: a Wallet home key unlocking the lock on approach, recorded on real
  hardware.
- `grid-demo-dark.webp` / `grid-demo-light.webp`: Home Key setup, Approach
  Direction, provisioning, NFC tap and live lock state on hardware.
- `twin-demo.webp`: the digital twin at the moment the firmware unlocks,
  captured from the live page with the noise switch off.
- `card.png` and `social-preview.png` (the `og:image`; `build.py` warns when
  it is absent).

Real, re-derivable numbers already on the surfaces:

- One timestamp tick is about 15.65 ps, which light crosses in 4.692 mm.
- Shipping DWM3001CDK image: flash 397,360 of 433,664 B (91.63%); RAM
  120,740 of 131,072 B (92.12%), measured with NCS v3.3.0 and
  `RELEASE=1 SMP=1`.
- The obstruction classifier costs 776 B flash, 0 B RAM, 28 B stack.
- 7,979 host tests, no hardware required.
- The unlock bound is 1.00 m, from `ULTRAWIDELOCK_UNLOCK_RANGE_CM`.

The landing hero computes its scope from the firmware's own constants in
`hero.js`, and `check_hero_constants.py` fails the build when they drift.

Absences that future work must not fabricate: there are no users, customers,
testimonials, press mentions, case studies, pricing, download counts, adoption
figures, or third party benchmarks. There is no claim of Aliro certification or
conformance testing. Repository defaults are bench defaults, and the project
states plainly that it should not be used to secure valuables.

## Product Principles

1. **Show the measurement, not a description of it.** The landing page opens
   with a live DS-TWR round computed from the firmware's constants. Every
   surface should prefer the real artifact over a picture of one.
2. **The browser is the on ramp.** A visitor with no board and no toolchain must
   still reach something real. The twin and the flasher are the product for the
   primary user, not demos placed beside it.
3. **Nothing generated is committed, and nothing lives outside the repository.**
   A fresh clone builds the whole site with stdlib Python.
4. **Claims are gated, not asserted.** Numbers on the page are re-checked
   against the code that produces them, and the build fails when they drift.
5. **State the limits on the surface.** Bench defaults, the Qorvo hardware
   restriction, no NFC tap on the DWM3001CDK, and a missing WASM build are said
   plainly rather than hidden.

## Accessibility & Inclusion

No standard was made binding during init. What the code already does, recorded
so future work keeps or changes it deliberately rather than by accident: a skip
link, `aria-current` on the active nav item, `aria-live` on the hero verdict,
`role="img"` with `<title>` and `<desc>` on the informational SVGs, a slider
alternative to the hero's drag interaction, and a light theme the design system
notes describe as holding AA. Treat this as the current floor, not a certified
level.
