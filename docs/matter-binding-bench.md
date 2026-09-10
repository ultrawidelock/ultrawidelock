# Bringing the binding up on hardware

The client half of `docs/matter-binding.md` has never exchanged a packet with a
real device: every gate it passes is the code agreeing with itself, down to a
loopback test running this node's initiator against its own responder. This
procedure finds out whether a Nuki, an Aqara or an ESP32 accepts it.

> **It has since been run, and it works.** 2026-08-22: a walk-up at the CDK
> opens `apps/nrf5340dk-lock` over Thread, and stepping away closes both. It
> took five runs, and each one stopped in a different quarter of the path --
> which is exactly what this document was written to make possible. The faults
> are listed under "What went wrong the first time" below, in the order they
> surfaced, because every one of them was a place the code agreed with itself
> and not with anybody else.
>
> Read the rest of this page as a bring-up procedure, not as a warning. What
> follows still applies to a peer that is NOT `apps/nrf5340dk-lock` -- a Nuki
> or an Aqara has met none of this.

**Expect it to fail the first time** against an untested peer. The run measures
which quarter of the path it stops in, not whether a door opens.

## Required hardware

| | | Why |
|---|---|---|
| 1x DWM3001CDK | the initiator | the thing under test |
| 1x peer lock | any Matter DoorLock server **on Thread** | `apps/nrf5340dk-lock`, a Nuki, or an Aqara U200 |
| 1x Thread Border Router | an Apple TV, a HomePod, or an OTBR | **mandatory.** This node runs no SRP server, so nothing resolves without one |
| a second controller | Home Assistant, or `chip-tool` | Apple Home alone cannot do this |

**The peer must be a Thread node.** The client resolves out of the Thread
network's SRP registrations (`_matter._tcp.default.service.arpa.`, in
`ports/zephyr/matter/matter_dns_port.c`); a Wi-Fi Matter device advertises over
mDNS and never appears there. `matter_thread_resolve()` is the only way in.

That rules out an ESP32-S3, which has no 802.15.4 radio, and
`apps/esp32-matter-lock` on every target including the C6: nothing in this repo
sets `CONFIG_ENABLE_MATTER_OVER_THREAD` or `CONFIG_OPENTHREAD_ENABLED`, so it
builds as a Wi-Fi node unless Thread is enabled and confirmed in
`build/esp32-matter-lock-<target>/sdkconfig`.

`apps/nrf5340dk-lock` is already Matter over Thread. Build it plain: `HA=1`
layers the LockOperation credential overlay for the automation path and is
unrelated to a binding. It demands no PIN
(`mRequirePINForRemoteOperation{ false }`), so a first run can leave the vendor
PIN attribute alone. Its devicetree always layers `dw3000-nfc.overlay`, so with
no DWM3000EVB expect `ultrawidelock_uwb_adapter_create_reader failed` in its
log; `make nrf-term` printing a pairing code confirms it came up.

`make nrf-build` refuses with `integration patch set changed or HA mode differs`
when the west workspace carries a different patch set than this tree expects.
`make ws-link` names each tree after the patch set in it, so a branch with its
own patches links its own tree (`make ws-store` lists them). The refusal remains
for the workspace `ULTRAWIDELOCK_WS=<path>` names directly: outside the store,
still one tree with one patch state.

Prefer an in-repo peer to a commercial lock on the first run: a Nuki gives a
silent drop with no way to tell a rejection from a lost packet, while a board
you built can be instrumented at both ends.

## Stage 0: build and flash

```
make build CLIENT=1          # bench: the client at DBG, no DFU receiver
make flash
make monitor
```

Without `CLIENT=1` no client code is compiled and the lock is unchanged.

Two profiles carry the client; for bringup use the first:

| build | client log level | fits by | what it is for |
|---|---|---|---|
| `make build CLIENT=1` | DBG | 294 B | the bench. Reads back why a bound lock did or did not open. No step-up, so a Watch is not learned on this image. |
| `make build CLIENT=1 RELEASE=1 SMP=1` | ERR (global level 1) | 8,288 B | what ships. mcumgr, DFU, signed. |

The debug profile fits only because `overlay-client-debug.conf` applies
automatically to `CLIENT=1` without `RELEASE=1`: it silences the credential, DFU
and radio log modules, drops the DFU receiver and turns off step-up (the Watch's
Access Document path). Read that file before adding
to it: setting a log symbol that does not exist aborts the CMake configure.

Neither profile has much room. If either stops linking or signing, that is the
size gate, not a broken tree: run `make cdk-size` and read the
`<- the one that ships` line, the only ceiling that counts.

For a signed image, `make release RELEASE_KEY=<path> CLIENT=1`. Leave
`make monitor` running for the whole session; the RTT log is the only
diagnostic.

## Stage 1: get both devices onto one fabric

1. Commission the CDK into Apple Home as normal.
2. Commission the peer lock into the same home.
3. Add **Home Assistant as a second administrator** to both, through Apple
   Home's "Turn On Pairing Mode".

If step 3 fails, check in this order:

- Firmware newer than 2026-08-07. Older builds cannot be added to any non-Apple
  controller and fail exactly as "pairing failed". See
  `docs/troubleshooting.md`.
- Both devices on **one** Thread network rather than two. This is the most
  common cause of a lock that pairs and then goes missing.
- The border router reachable.

Home Assistant is needed because **Apple Home will not write a binding**. It is
used once, at setup, and is not in the unlock path.

## Stage 2: prove the peer before involving this node

**Do not skip this.** Do not debug two unknowns at once.

1. From Home Assistant or `chip-tool`, invoke `UnlockDoor` on the peer lock
   directly. If the door does not open, stop: nothing after this point means
   anything.
2. Note the CDK's **operational node id on the Home Assistant fabric**: needed
   next, and the value most often got wrong.

## Stage 3: write the two attributes

1. **On the peer lock:** an ACL entry granting the CDK's node id `Operate`
   privilege on the DoorLock cluster.
2. **On the CDK:** the Binding attribute, naming the peer's node id, its
   endpoint (usually 1), and the DoorLock cluster.
3. **If the peer wants a PIN:** write it to the vendor PIN attribute on the CDK.
   It is write-only and never reads back.

`scripts/bind-helper.py` does both ends through `chip-tool`; the commands, the
attribute paths and the tag-keyed structures are in `docs/matter-binding.md`.
Read the binding back before continuing.

**`chip-tool` is not required.** The 2026-08-22 bring-up wrote both attributes
through Home Assistant's Matter server websocket (`ws://<ha-host>:5580/ws`, no
token). Prefer it: a binding is fabric-scoped, so whichever administrator writes
it owns the fabric the CASE session runs on forever, and a `chip-tool` fabric's
keys live in a laptop directory that takes the binding with it when deleted.

An ACL write REPLACES that fabric's entries: read the list, keep the
administrator's own entry, append yours, and write the set back.

A successful bench write:

```
CDK  1/30/0  ->  [{1:7, 3:1, 4:257, 254:3}]              binding to node 7
DK   0/31/0  ->  [ ... {1:5,2:2,3:[112233],254:3},       HA's admin, KEPT
                       {1:3,2:2,3:[6],4:[{0:257,1:1}],254:3} ]   node 6, Operate
```

## Stage 4: the run

Walk up with an enrolled phone. **Once.** A second attempt overlaps the first's
backoff and makes the log ambiguous.

The CDK prints a line at each step, so where the log stops is the diagnosis:

| Last line you see | It got as far as | Look at |
|---|---|---|
| nothing | the gate never fired | the UWB grant, not Matter. `matter_client_want()` is called only on a granted unlock |
| `resolving bound peer <instance>` | DNS-SD query sent, no answer | the border router, the peer's SRP registration, and whether both are on ONE Thread network |
| `bound peer has a service but no address yet` | SRV found, no AAAA behind it | the peer's host registration has expired while its service has not. Was once the ordinary case; see the DNS fix below |
| `bound peer resolved: port n` | we know where to send | the handshake, next row |
| `Sigma1 out to node ...` | the handshake started, no Sigma2 came back | the peer's own log. A CHIP peer says whether it matched the destination id |
| `Sigma2: chain not from this fabric root (-6)` | the certificate did not verify to our root | genuinely the wrong fabric -- or, once, our own verifier. See below |
| `Sigma2: bound 0x..., answered 0x...` | right fabric, wrong node answered | the binding's node id, against the peer's id ON THIS FABRIC |
| `Sigma3 out: session ...` | we accepted the peer and answered | the peer is verifying our signature. No StatusReport means it refused |
| `CASE ESTABLISHED as initiator` | the handshake is done | the invoke, below |
| `the bound lock refused the timed window` | the peer would not open a timed window | rare; a peer that does this refuses the invoke too |
| `UnlockDoor out: endpoint n` | the command is on the air | the peer's ACL. `UNSUPPORTED_ACCESS` is the expected answer to a missing entry |
| `the bound lock stopped answering mid-unlock` | the command went out and died | the peer DROPPED it. See the MRP ack fix below |
| `the bound lock UNLOCKED` | it worked | stop reading |
| `LockDoor out` / `the bound lock LOCKED` | the departure propagated too | nothing. Both doors are shut |

A chain failure is `MATTER_E_TYPE` (-6) and an identity mismatch is
`MATTER_E_ACCESS` (-9). Both were -9 until 2026-08-22, so a chain fault read as
the wrong node answering.

## What is most likely to be wrong

Ranked, and what is left has never been exercised.

### 1. No peer but `apps/nrf5340dk-lock` has ever answered

CHIP has put cryptographically valid Sigma2 messages in front of the CASE
initiator, but only from this repo's own DK. A second peer implementation is the
only thing that finds the next fault.

**Signature:** anything, on a peer that is not the DK.

### 2. An outstanding DNS-SD query blocks the next attempt

`matter_thread_resolve()` refuses a second query while one is outstanding, and
nothing in the client can cancel one. An attempt that times out after
`MATTER_CLIENT_STEP_MS` can leave a query behind that blocks the NEXT attempt,
for a duration that is OpenThread's business and cannot be pinned down off
hardware.

**Signature:** the first walk-up produces `resolving`, a second a few seconds
later produces nothing: no log line, no datagram. It recovers once the query
completes.

**Covered by a test** (`a query still outstanding blocks the next attempt`); the
duration on a real mesh is unknown.

### 3. The Sigma1 source node id: checked, and NOT a blocker

This node puts its **operational** node id in the message header's source field
rather than a random ephemeral one. The deviation from CHIP is real but is not a
failure mode:

- CHIP generates its ephemeral initiator node id as a random 64-bit value
  **constrained to the operational node id range**
  (`SessionManager::CreateUnauthenticatedSession`), so the value this node sends
  is indistinguishable in form from CHIP's.
- The responder uses it as an opaque key to find or allocate an unauthenticated
  session (`SessionManager::OnMessageReceived` -> `FindOrAllocateResponder`) and
  validates nothing beyond its presence.

The cost is **privacy**: the value is stable rather than per-session, so a
passive Thread observer can link every handshake this node makes to one
identity. Worth fixing; not worth suspecting on the bench.

### 4. Retransmission: now implemented for the handshake

A dropped Sigma1 or Sigma3 is resent on an MRP timer rather than costing the
whole `MATTER_CLIENT_STEP_MS`. The first resend lands at roughly four times
`MATTER_MRP_IDLE_INTERVAL_MS`: the deadline carries MRP's margin and backoff
multipliers.

The **interaction** past the session is still not covered: those messages are
sealed by `matter_exchange`, whose counters `matter_client.c` does not own.

**Signature of the remaining gap:** intermittent failure after
`CASE ESTABLISHED`, correlating with mesh quality, where the retry restarts
from `resolving` rather than resuming the invoke.

## What went wrong the first time

Five faults, in the order they surfaced on 2026-08-22. Each hid the next. All
five passed every host gate: a test that signs its own certificates and encodes
its own messages agrees with a verifier that makes the same mistake.

**1. A chunked list write was refused whole.** Matter writes a list as
replace-all followed by one `AppendItem` per member, so ONE attribute arrives as
several data blocks. This node counted blocks, called anything past the first a
batch and answered `RESOURCE_EXHAUSTED` without applying any of it, so Home
Assistant could not write the binding or any other list attribute, including an
ACL. Blocks naming one attribute are now coalesced before the cluster sees them.

*Signature:* a write that returns status 137 with the attribute unchanged, and a
`write:` line in the log whose byte count is 3, the empty replace-all being the
only block parsed.

**2. DNS-SD found the service and not the address.**
`otDnsClientResolveService()` reports an address only when the server volunteers
one in the Additional Data section of the SRV answer. This border router does
not. It now uses `otDnsClientResolveServiceAndHostAddress()`, which sends the
follow-up AAAA query.

*Signature:* `bound peer has a service but no address yet`.

**3. Certificates were verified over the wrong bytes.** A Matter certificate is
TLV, but the signature it carries is the X.509 one over the DER-encoded
`TBSCertificate`. This node hashed the TLV span, which verifies only a
certificate signed the same wrong way, and the test fixture signed its
certificates exactly that way, so 8,000 green assertions said nothing. The
responder does not walk chains, so this code ran only on the client path, which
had never met a peer. The converter is now pinned to CHIP's own output for a
reference certificate, compared by SHA-256.

*Signature:* every real certificate rejected, reported as an identity mismatch
because `cert_verify()` returned `MATTER_E_ACCESS` for a signature failure. That
conflation is fixed too.

**4. The MRP ack did not ride the invoke.** Framing refused to piggyback a
pending acknowledgement on any exchange this node had opened. Right for a NEW
exchange, wrong for the second message of one: CHIP does not wait for the ack it
is owed, it DROPS the request. The `UnlockDoor` after a `TimedRequest` was
discarded every time.

*Signature:* `the bound lock stopped answering mid-unlock`, and on a CHIP peer,
`Dropping message without piggyback ack when we are waiting for an ack`.

**5. Only the unlock was ever forwarded.** The bound lock opened and never
closed. `matter_client_want()` now takes the bolt's STATE rather than signalling
an event, and the client reconciles what is wanted against what the peer last
accepted. Forwarding both edges would not have sufficed: the state machine
clears its pending want when an invoke completes, so a relock arriving during an
unlock was swallowed.

*Signature:* the peer stays unlocked after a walk-away.

## Faults already fixed, and their signatures

A capture showing one of these is a regression, not a new diagnosis.

### A retransmitted StatusReport with nowhere to go

The peer sets R on the StatusReport that ends CASE and retransmits until
acknowledged. This node acknowledges once, so a lost acknowledgement used to
leave the retransmission unroutable: the handshake flag had already cleared, and
a Secure Channel message that is neither Sigma1 nor Sigma3 falls into the
unsecured drop. The handshake exchange now lingers for `CLIENT_HS_LINGER_MS`
after success and answers a repeat with another acknowledgement.

**Signature if it returns:** `CASE ESTABLISHED` here, the peer still
retransmitting, and the invoke failing against a session the peer is tearing
down. Intermittent, so it presents as "works sometimes".

### A fabric pointer outliving its fabric

`s_fabric` points into the fabric table, and a RemoveFabric that zeroes the slot
left it addressing valid memory describing nothing. The Sigma1 path tested for
NULL, which a cleared slot is not.

It is tested for liveness now: a fresh lookup by index, the slot still
committed, and the fabric id unchanged. An attempt whose administrator has gone
is dropped rather than signed with a zeroed key. The fabric id matters because a
slot is an array position: an administrator removed and another commissioned
into it returns the same pointer at the same index, describing somebody else.
The check also runs on the inbound path, from the receive callback, ahead of the
poll that would notice.

**Signature if it returns:** only after removing an administrator without
rebooting. A Sigma1 refused by everything, with the log naming a fabric that is
gone. In the reused-slot form, the worst outcome on this page: an unlock sent on
behalf of an administrator that was removed.

### A handshake the schedule had given up on, still holding its exchange

`matter_client_sm_poll()` leaves the Sigma1 state on its own deadline and tells
nobody. Nothing cleared the client's handshake flag, so an abandoned attempt
kept its ephemeral private key and transcript in RAM indefinitely, kept its
exchange id claimed against every inbound unsecured message, and would open a
Sigma2 arriving long afterwards as though somebody were still waiting.

**Signature if it returns:** `CASE ESTABLISHED` appearing with no walk-up behind
it, minutes after a failed attempt. Also a Sigma1 addressed to THIS node
silently dropped, because the client still claims an exchange id it should have
released.

### The retransmit timer dropped by any inbound message

The retransmission deadline was folded into the timer in the poll only, while
two other paths re-arm the same timer when a datagram arrives. Any inbound
message that did not acknowledge the outstanding one re-armed from the schedule
alone, silently cancelling the pending resend.

**Signature if it returns:** resends that happen when the peer is silent and
stop the moment it says anything at all.

### `matter_client_init()` that did not initialise

Init set up the lock and the pointers but left the session, handshake and
handshake-linger state as the previous run had them. Harmless on target, where
it runs once; fatal to reasoning about the file's starting state.

## What to capture

`make monitor` from the first walk-up through two full retries: the backoff
doubling is visible in the second and confirms the state machine is running.

From the peer, whatever it prints on datagram receipt. If the ESP32 shows
nothing, the problem is Thread routing, not either Matter implementation.

Record the result in `docs/hardware-validation.md` as a new row when it passes.
