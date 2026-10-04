#!/usr/bin/env python3
"""cdk-stack-depth.py — how deep the stack goes below a function, from a listing.

The DWM3001CDK runs its stacks within a few hundred bytes of their size, and
the optimiser decides most of the depth: which handlers it folds into their
caller changes from build to build, and a frame that stays out of line goes on
top of a caller frame already sized for the ones folded in. The paint
(docs/dwm3001cdk-surgery.md 1.3) says what a board has used so far. This says
what a build can use, before it is flashed, and which call chain does it.

    arm-zephyr-eabi-objdump -d --no-show-raw-insn \\
        build/cdk-matter/dwm3001cdk-lock/zephyr/zephyr.elf > /tmp/cdk.dis
    scripts/cdk-stack-depth.py /tmp/cdk.dis transaction_feed command

    scripts/cdk-stack-depth.py --frames 600 /tmp/cdk.dis   # every frame >= 600 B

WHAT IT COUNTS. A frame is the registers a function pushes plus every constant
it takes off the stack pointer. An edge is a direct call or tail branch to
another function. Indirect calls (callbacks, the PSA driver table) are not
followed, and neither is anything above the root, so the figure is a LOWER
BOUND on the real depth. It is the same lower bound for two builds of one
source, and that comparison is what it is for.
"""
import argparse
import re
import sys

sys.setrecursionlimit(20000)

LABEL = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
PUSH = re.compile(r"\t(?:push|stmdb\s+sp!,)\s*\{([^}]*)\}")
VPUSH = re.compile(r"\tvpush\s*\{([^}]*)\}")
SUB_SP = re.compile(r"\tsub(?:w|\.w)?\s+sp,(?:\s*sp,)?\s*#(\d+)")
BRANCH = re.compile(r"\t(?:bl|b\.w|b\.n|b)\s+[0-9a-f]+ <([^>+]+)>")
LTO_SUFFIX = re.compile(r"\.(?:lto_priv|constprop|part|isra|cold)\.?\d*")


def normalise(name):
    """Drop the suffixes LTO adds, so one function has one name across builds."""
    return LTO_SUFFIX.sub("", name)


def load(lines):
    """Return ({function: frame bytes}, {function: set of callees})."""
    frame, calls = {}, {}
    name = None
    for line in lines:
        m = LABEL.match(line)
        if m:
            name = normalise(m.group(1))
            frame.setdefault(name, 0)
            calls.setdefault(name, set())
            continue
        if name is None:
            continue
        m = PUSH.search(line)
        if m:
            frame[name] += 4 * len([r for r in m.group(1).split(",") if r.strip()])
            continue
        m = VPUSH.search(line)
        if m:
            frame[name] += 8 * max(1, len(m.group(1).split(",")))
            continue
        m = SUB_SP.search(line)
        if m:
            frame[name] += int(m.group(1))
            continue
        m = BRANCH.search(line)
        if m:
            target = normalise(m.group(1))
            if target != name:
                calls[name].add(target)
    return frame, calls


def deepest(frame, calls, root):
    """Return (bytes, chain) for the deepest direct-call path starting at root."""
    memo, on_path = {}, set()

    def walk(fn):
        if fn in memo:
            return memo[fn]
        if fn in on_path or fn not in frame:
            return 0, []
        on_path.add(fn)
        best, chain = 0, []
        for callee in calls.get(fn, ()):
            depth, sub = walk(callee)
            if depth > best:
                best, chain = depth, sub
        on_path.discard(fn)
        memo[fn] = (frame[fn] + best, [fn] + chain)
        return memo[fn]

    return walk(root)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("listing", help="objdump -d output, or - for stdin")
    ap.add_argument("roots", nargs="*", help="functions to measure below")
    ap.add_argument("--frames", type=int, metavar="BYTES",
                    help="list every function whose own frame is at least BYTES")
    ap.add_argument("--chain", type=int, default=8, metavar="N",
                    help="how many functions of the deepest chain to print (default 8)")
    args = ap.parse_args()

    src = sys.stdin if args.listing == "-" else open(args.listing, errors="replace")
    frame, calls = load(src)
    if not frame:
        sys.exit("no functions found: is this objdump -d output?")

    status = 0
    if args.frames is not None:
        for size, name in sorted(((s, n) for n, s in frame.items() if s >= args.frames),
                                 reverse=True):
            print("%6d B  %s" % (size, name))
    for root in args.roots:
        if root not in frame:
            print("%-28s absent (folded into its caller, or misspelt)" % root)
            status = 1
            continue
        total, chain = deepest(frame, calls, root)
        shown = " > ".join("%s(%d)" % (fn, frame[fn]) for fn in chain[:args.chain])
        more = " > ..." if len(chain) > args.chain else ""
        print("%-28s %5d B  %s%s" % (root, total, shown, more))
    return status


if __name__ == "__main__":
    sys.exit(main())
