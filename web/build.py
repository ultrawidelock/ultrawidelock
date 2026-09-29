#!/usr/bin/env python3
"""Build the UltraWideLock site into web/dist/.

Two rules, both learned from the generator this replaces:

  1. Nothing generated is ever committed. The old pipeline wrote a page per
     source file into docs/ and committed them; every merge then conflicted on
     derived line numbers, which no resolution could settle and only a
     regeneration could fix. web/dist/ is gitignored and disposable.

  2. No tool outside this repository. The old pipeline looked for a page
     generator on a machine-local path, so a fresh clone could not build the
     site at all. This is stdlib-only Python and needs nothing installed.

Usage:
    python3 web/build.py            # build into web/dist/
    python3 web/build.py --check    # build, then fail on any dead internal link
    python3 web/build.py --refresh-graph   # also rewrite the committed graph
                                           # distillate from graphify-out/
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

WEB = Path(__file__).resolve().parent
ROOT = WEB.parent
DIST = WEB / "dist"

# Copied verbatim into the output. Source directory -> published path,
# where "" is the site root.
TREES = {
    WEB / "site": "",
    WEB / "assets" / "design": "assets/design",
    WEB / "flasher": "flash",
    WEB / "twin": "twin",
}

# Files inside those trees that are build-time or test-time only. .pyc matters
# as much as .py: importing markdown.py leaves a __pycache__ beside it, and
# that is bytecode of a build script, published next to the pages it rendered.
NOT_PUBLISHED = {".py", ".pyc", ".cjs", ".c", ".sh"}


def clean() -> None:
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)
    # GitHub Pages runs Jekyll unless told not to, and Jekyll drops every path
    # starting with an underscore. Nothing here needs Jekyll, so opt out rather
    # than depend on no future asset ever being named that way.
    (DIST / ".nojekyll").touch()


# ---------------------------------------------------------------- the shell --
# Every page's chrome is generated from here rather than pasted into each
# source file. Before this, the topbar existed in four versions that had already
# drifted: the landing page had a theme toggle, the docs template had none, the
# twin persisted its choice under a different localStorage key than the rest of
# the site, and the 3D graph had no toggle at all and a bootstrap that ignored a
# saved light preference on a dark-preferring OS.

SITE = "https://ultrawidelock.com"
GITHUB = "https://github.com/ultrawidelock/ultrawidelock"

# The navigable surface, in nav order: path from the site root -> label.
# The graph is conditional; see nav().
NAV = (
    ("docs/index.html", "Docs"),
    ("twin/index.html", "Twin"),
    ("flash/index.html", "Flash"),
    ("graph/index.html", "Graph"),
)

# Set once in main(), read by nav(). The graph is the one page that may not
# exist: it needs graphify, which is not in this repository. Linking it anyway
# published a nav item that 404'd on every build without graphify-out/ -- the
# link gate deliberately excuses that path, so nothing caught it.
HAVE_GRAPH = False

# Set once in main() from --refresh-graph. Off by default: rewriting the
# committed distillate on every build left a dirty tree in every worktree that
# had graphify data, and since its first line is the commit the graph was
# extracted at, two branches that both built conflicted there on every merge.
REFRESH_GRAPH = False

# Runs before the stylesheet so the first paint is already the right theme.
# Inline and tiny on purpose: a separate file would be a round trip during
# which the wrong theme is on screen.
THEME_BOOT = ("<script>(function(){try{var t=localStorage.getItem('uwl-theme');"
              "if(t)document.documentElement.setAttribute('data-theme',t);}"
              "catch(e){}})();</script>")

# Marks the document as scripted before any CSS runs, so the reveal animations
# only hide their content when there is JavaScript present to bring it back.
# Without this a reader with JS off gets a page of invisible sections.
#
# `booted` is the same idea one step further, and it is the only thing that
# starts the landing page's opening sequence. It is set here, ahead of the
# stylesheet, rather than from a deferred script, because a class added after
# the first paint would show the hero and then hide it to animate it back. The
# sequence itself is pure animation-delay in landing.css; nothing schedules it,
# nothing repeats it, and no script runs while it plays.
JS_FLAG = "<script>document.documentElement.className+=' js booted';</script>"


def rel_to_root(depth: int) -> str:
    """Prefix that walks from a page `depth` levels down back to the site root."""
    return "../" * depth


def head(title: str, desc: str, depth: int, canon: str, *,
         extra: str = "") -> str:
    """The <head> every page shares.

    The font preloads matter more than they look. Fonts are only discovered
    once the stylesheet has been fetched and parsed, so without these the two
    faces start downloading a full round trip late and the page swaps under the
    reader. Preloading moves them onto the wire beside the CSS.
    """
    rel = rel_to_root(depth)
    return f"""<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html_escape(title)}</title>
<meta name="description" content="{html_escape(desc)}">
<link rel="canonical" href="{SITE}/{canon}">
<meta property="og:type" content="website">
<meta property="og:title" content="{html_escape(title)}">
<meta property="og:description" content="{html_escape(desc)}">
<meta property="og:url" content="{SITE}/{canon}">
<meta property="og:image" content="{SITE}/assets/social-preview.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="{rel}assets/favicon.svg" type="image/svg+xml">
<link rel="preload" as="font" type="font/woff2" crossorigin
      href="{rel}assets/design/fonts/space-grotesk.woff2">
<link rel="preload" as="font" type="font/woff2" crossorigin
      href="{rel}assets/design/fonts/jetbrains-mono.woff2">
{THEME_BOOT}
{JS_FLAG}
<link rel="stylesheet" href="{rel}assets/design/styles.css">{extra}"""


THEME_BTN = ('<button class="icon-btn" data-theme-toggle aria-pressed="false" '
             'title="Switch theme" aria-label="Switch theme">'
             '<svg class="sun" viewBox="0 0 16 16" aria-hidden="true" fill="currentColor">'
             '<circle cx="8" cy="8" r="4"/><circle cx="8" cy="1.4" r="1.1"/>'
             '<circle cx="8" cy="14.6" r="1.1"/><circle cx="1.4" cy="8" r="1.1"/>'
             '<circle cx="14.6" cy="8" r="1.1"/></svg>'
             '<svg class="moon" viewBox="0 0 16 16" aria-hidden="true" fill="currentColor">'
             '<path d="M8 1a7 7 0 1 0 7 7 5.5 5.5 0 0 1-7-7Z"/></svg></button>')

NAV_BTN = ('<button class="icon-btn navtoggle" data-nav-toggle aria-expanded="false" '
           'aria-controls="navlinks" aria-label="Menu">'
           '<svg viewBox="0 0 16 16" aria-hidden="true" fill="currentColor">'
           '<rect x="2" y="4" width="12" height="1.6" rx=".8"/>'
           '<rect x="2" y="7.2" width="12" height="1.6" rx=".8"/>'
           '<rect x="2" y="10.4" width="12" height="1.6" rx=".8"/></svg></button>')


def nav(depth: int, current: str = "") -> str:
    """The sticky topbar. `current` is a root-relative path, "" for home."""
    rel = rel_to_root(depth)
    links = []
    for path, label in NAV:
        if path.startswith("graph/") and not HAVE_GRAPH:
            continue
        here = ' aria-current="page"' if path == current else ""
        links.append(f'<a class="navlink" href="{rel}{path}"{here}>{label}</a>')
    links.append(f'<a class="navlink" href="{GITHUB}" data-ext>Source</a>')
    home = ' aria-current="page"' if not current else ""
    return (f'<header class="topbar">'
            f'<a class="wordmark" href="{rel}index.html"{home}>UltraWideLock '
            f'<span class="ver">v0.4.0</span></a>'
            f'<div class="spacer"></div>'
            f'<nav class="navlinks" id="navlinks" aria-label="Main">'
            f'{"".join(links)}</nav>'
            f'{THEME_BTN}{NAV_BTN}</header>')


def footer(depth: int) -> str:
    rel = rel_to_root(depth)
    graph = (f'<a href="{rel}graph/index.html">Subsystem graph</a>'
             if HAVE_GRAPH else "")
    return f"""<footer class="footer">
  <div class="footer-in">
    <div class="footer-col">
      <a class="wordmark" href="{rel}index.html">UltraWideLock <span class="ver">v0.4.0</span></a>
      <p class="fine">Portable firmware for NFC and UWB smart locks, on nRF52833, nRF5340 and ESP32.
      ISC licensed.</p>
    </div>
    <div class="footer-col">
      <span class="footer-cap">Docs</span>
      <a href="{rel}docs/index.html">All guides</a>
      <a href="{rel}docs/troubleshooting.html">Troubleshooting</a>
      <a href="{rel}docs/porting.html">Porting</a>
    </div>
    <div class="footer-col">
      <span class="footer-cap">Tools</span>
      <a href="{rel}twin/index.html">Digital twin</a>
      <a href="{rel}flash/index.html">Web flasher</a>
      {graph}
    </div>
    <div class="footer-col">
      <span class="footer-cap">Source</span>
      <a href="{GITHUB}" data-ext>github.com/ultrawidelock</a>
      <a href="{GITHUB}/blob/main/LICENSE" data-ext>LICENSE (ISC)</a>
      <a href="{GITHUB}/blob/main/CONTRIBUTING.md" data-ext>Contributing</a>
      <a href="{GITHUB}/blob/main/SECURITY.md" data-ext>Security</a>
    </div>
  </div>
  <div class="footer-bar">
    <span>ISC &middot; no CLA</span>
    <span>built static, works offline</span>
    <span>bench defaults, not a product</span>
  </div>
</footer>
<script src="{rel}assets/design/site.js" defer></script>"""


def html_escape(text: str) -> str:
    return html.escape(text, quote=True)


def shell(page: str, depth: int, current: str = "") -> str:
    """Substitute the shared chrome into a page source."""
    return (page.replace("@@HEAD@@", "")          # pages build their own head
                .replace("@@NAV@@", nav(depth, current))
                .replace("@@FOOTER@@", footer(depth)))


# ------------------------------------------------------------- asset bundle --
# Authoring order. Tokens first (nothing can reference a variable that has not
# been declared as a fallback target), then the reset, then components, then the
# two page-scoped sheets.
CSS_PARTS = (
    "tokens/typography.css",
    "tokens/scale.css",
    "tokens/colors.css",
    "tokens/reset.css",
    "components.css",
    "landing.css",
    "docs.css",
)

# theme.js first: it defines the toggle behaviour site.js wires up.
JS_PARTS = ("js/theme.js", "js/site.js")

COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
BLANKS_RE = re.compile(r"\n{2,}")


def bundle_css() -> Path:
    """Concatenate the design system into one stylesheet.

    styles.css used to be five @import lines. An @import cannot be discovered
    until the sheet containing it has already arrived and been parsed, so that
    was a five-deep serial fetch chain in front of the first paint of every
    page -- the single most expensive thing about the old build. The sources
    stay split for authoring; only the output is joined.
    """
    src = WEB / "assets" / "design"
    out = DIST / "assets" / "design" / "styles.css"
    out.parent.mkdir(parents=True, exist_ok=True)

    chunks = []
    for part in CSS_PARTS:
        path = src / part
        if not path.is_file():
            raise SystemExit(f"build: missing stylesheet {path}")
        body = COMMENT_RE.sub("", path.read_text(encoding="utf-8"))
        chunks.append(BLANKS_RE.sub("\n", body).strip())
    out.write_text("\n".join(chunks) + "\n", encoding="utf-8")
    return out


def bundle_js() -> list[Path]:
    """One deferred bundle for the shared behaviour, one for the landing hero.

    The hero is a separate file because it is ~9 KB that only one page uses,
    and it is the only script on the site heavy enough for that to matter.
    """
    src = WEB / "assets" / "design"
    written = []

    out = DIST / "assets" / "design" / "site.js"
    out.parent.mkdir(parents=True, exist_ok=True)
    chunks = []
    for part in JS_PARTS:
        path = src / part
        if not path.is_file():
            raise SystemExit(f"build: missing script {path}")
        chunks.append(path.read_text(encoding="utf-8").strip())
    # Not minified: these are small, they gzip well, and a regex JS minifier
    # that has to tell a regex literal from a division is a bug generator.
    out.write_text("\n".join(chunks) + "\n", encoding="utf-8")
    written.append(out)

    hero = src / "js" / "hero.js"
    if hero.is_file():
        dest = DIST / "assets" / "design" / "hero.js"
        shutil.copy2(hero, dest)
        written.append(dest)
    return written


FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
<rect width="32" height="32" rx="7" fill="#061012"/>
<circle cx="9" cy="16" r="3.2" fill="#2ee6b8"/>
<path d="M14.5 10.2a8 8 0 0 1 0 11.6" fill="none" stroke="#2ee6b8"
      stroke-width="2.2" stroke-linecap="round" opacity=".72"/>
<path d="M19.6 6.4a13.6 13.6 0 0 1 0 19.2" fill="none" stroke="#2ee6b8"
      stroke-width="2.2" stroke-linecap="round" opacity=".38"/>
</svg>
"""


def emit_meta(pages: list[str]) -> list[Path]:
    """CNAME, robots.txt, sitemap.xml, favicon.

    `pages` is the list of root-relative page paths that should be indexed.
    """
    written = []

    def put(rel_path: str, body: str) -> None:
        dest = DIST / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding="utf-8")
        written.append(dest)

    # Custom domain. Every internal link on the site is relative, so dropping
    # this file is all it takes to serve from a project subpath instead.
    put("CNAME", "ultrawidelock.com\n")
    put("robots.txt", f"User-agent: *\nAllow: /\n\nSitemap: {SITE}/sitemap.xml\n")
    put("assets/favicon.svg", FAVICON)

    urls = "".join(
        f"  <url><loc>{SITE}/{p}</loc></url>\n"
        for p in sorted(pages))
    put("sitemap.xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{urls}</urlset>\n")

    # A 404 that carries the site's own chrome, so a bad link lands somewhere
    # navigable instead of on GitHub's default page.
    put("404.html", f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
{head("Page not found — UltraWideLock",
      "That page is not here. The guides, the twin, the flasher and the source are.",
      0, "404.html")}
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
{nav(0)}
<main id="main" class="page" style="padding-top:var(--sp-20);padding-bottom:var(--sp-20)">
  <span class="eyebrow">404</span>
  <h1 style="font-size:var(--fs-900);color:var(--strong);margin:0 0 var(--sp-4)">
  That page is not here.</h1>
  <p class="lede" style="margin-bottom:var(--sp-8)">The link may be from an older
  layout of this site. Everything below still is.</p>
  <ul class="rows mono">
    <li><a href="index.html"><span class="row-name">home</span><span class="row-desc">what this firmware is, and how a door opens</span></a></li>
    <li><a href="docs/index.html"><span class="row-name">guides</span><span class="row-desc">bring-up, porting and bench notes</span></a></li>
    <li><a href="twin/index.html"><span class="row-name">twin</span><span class="row-desc">the ranging stack, running in the page</span></a></li>
    <li><a href="flash/index.html"><span class="row-name">flash</span><span class="row-desc">write an ESP32 image over a cable, or update a board over the air</span></a></li>
    <li><a href="{GITHUB}" data-ext><span class="row-name">source</span><span class="row-desc">github.com/ultrawidelock</span></a></li>
  </ul>
</main>
{footer(0)}
</body>
</html>
""")
    return written


def build_twin_wasm() -> bool:
    """Compile the twin's firmware to WASM. Needs emscripten; skipping is fine.

    The page degrades to an explanation rather than a broken simulator, so a
    contributor without emcc can still build and read the whole site.
    """
    script = WEB / "twin" / "build-wasm.sh"
    if shutil.which("emcc") is None:
        print("build: emcc not found, twin simulator will be absent "
              "(brew install emscripten)")
        return False
    result = subprocess.run(["bash", str(script)], capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr.strip()[-2000:], file=sys.stderr)
        raise SystemExit("build: twin WASM failed")
    print(f"build: {result.stdout.strip()}")
    return True


def graph_source() -> Path | None:
    """Where the subsystem graph's data comes from, freshest first.

    graphify's own output is 11 MB of 7,969 nodes, machine-local and gitignored,
    and this page reduces all of it to 17 subsystems and 49 edges. So the
    repository carries the 3 KB reduction instead: the graph page then builds
    from a fresh clone, in CI, and on a machine that has never heard of
    graphify -- which is the whole point of this build's second rule.

    When the full graph is present it wins as the render's source, but the
    committed distillate is only rewritten under --refresh-graph. Refreshing is
    a deliberate command, `make docs-graph-refresh`, that produces one
    reviewable commit; see REFRESH_GRAPH for why it is not a side effect of
    every build.
    """
    sys.path.insert(0, str(WEB / "graph"))
    import graph as graph_mod                                   # noqa: PLC0415
    import graph3d                                              # noqa: PLC0415
    import json as _json                                        # noqa: PLC0415

    full = ROOT / "graphify-out" / "graph.json"
    if full.is_file():
        data = _json.loads(full.read_text())
        distillate = graph_mod.DISTILLATE.relative_to(ROOT)
        payload = graph3d.PAYLOAD.relative_to(ROOT)
        # Both committed files come from this one graph, so one refresh writes
        # both: a run that updated the subsystems and left the file-level page
        # a release behind would be the more confusing half-state.
        built = graph3d.build(data, ROOT)
        if REFRESH_GRAPH:
            for name, changed in ((distillate, graph_mod.write_distillate(data)),
                                  (payload, graph3d.write_payload(built))):
                print(f"build: refreshed {name} from graphify-out/ (commit it)"
                      if changed else
                      f"build: {name} already matches graphify-out/")
        else:
            # Says it out loud rather than writing: this build renders from the
            # full graph, so a stale committed file is invisible here and shows
            # up only on a fresh clone or in CI.
            for name, current in ((distillate,
                                   graph_mod.distillate_is_current(data)),
                                  (payload, graph3d.payload_is_current(built))):
                if not current:
                    print(f"build: {name} is behind graphify-out/ "
                          "(make docs-graph-refresh)")
        return full
    if graph_mod.DISTILLATE.is_file():
        return graph_mod.DISTILLATE
    print("build: no graph data, skipping the graph "
          "(graphify update .)")
    return None


def build_graph() -> Path | None:
    """Render the subsystem graph."""
    source = graph_source()
    if source is None:
        return None
    sys.path.insert(0, str(WEB / "graph"))

    out = DIST / "graph" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)

    # The 3D page needs node-level data and the vendored renderer. The data is
    # committed as web/graph/files.json, so graphify's absence no longer decides
    # this; the renderer is 1.3 MB of three.js, still fetched rather than
    # committed, by `make docs-graph3d` locally and by the pages workflow in CI.
    # Without it the flat SVG still builds, which is the fallback and not the
    # published default any more.
    lib = WEB / "vendor" / "3d-force-graph.min.js"
    import graph as graph_mod                                    # noqa: PLC0415
    import graph3d                                               # noqa: PLC0415
    node_level = (source if source != graph_mod.DISTILLATE
                  else graph3d.PAYLOAD if graph3d.PAYLOAD.is_file() else None)

    if lib.is_file() and node_level is not None:
        out.write_text(graph3d.render(node_level, ROOT), encoding="utf-8")
        shutil.copy2(lib, out.parent / lib.name)
        print(f"build: 3D graph from {node_level.name} -> "
              f"{out.relative_to(DIST)}")
    else:
        out.write_text(graph_mod.render(source), encoding="utf-8")
        why = ("3d-force-graph not vendored, `make docs-graph3d`"
               if node_level is not None
               else "no node-level graph data, `graphify update .`")
        print(f"build: flat graph from {source.name} ({why})")
    return out


# Guides live in docs/ rather than under web/, deliberately: they are read
# directly on GitHub and release/*/FLASH.md links into them by path. The build
# treats that directory as another source tree instead of moving them.
DOCS = ROOT / "docs"


# The reading order of the guides, grouped. Ordering them by filename put
# "Add the key" first and "Troubleshooting" in the middle of the board
# bring-ups, which is not how anyone reads them. Anything not named here still
# appears, under "More" -- a curated list must not be able to hide a new file.
DOC_GROUPS = (
    ("Start", ("specification", "configuring", "add-the-key",
              "troubleshooting")),
    ("Boards", ("esp32-bringup", "esp32-gotchas", "nrf5340-bringup",
                "nrf5340-wiring", "dwm3001cdk-surgery", "hardware-validation")),
    ("Porting", ("porting", "porting-esp32", "chipset-memory")),
    ("Protocol", ("protocol-notes", "protocol-research", "range-integrity",
                  "approach-direction", "uwb-mac-login",
                  "matter-door-lock-events", "matter-binding",
                  "matter-binding-bench", "bodycal-falsification")),
    # Inside versus outside is a subject, not a board and not the protocol:
    # the design, the ranging route that replaces it, and the two runbooks
    # that prove either one on a bench. Filed under Protocol they read as
    # wire format, which is the one thing they are not.
    ("Side of the door", ("inside-latch", "second-anchor",
                          "bench-inside-outside")),
    ("Reference", ("reference",)),
)


def _title_of(md: Path) -> str:
    for line in md.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return md.stem.replace("-", " ")


def _summary_of(md: Path) -> str:
    """First real sentence of a guide, for the index cards and meta description.

    The index used to print the filename stem as every guide's description,
    which told a reader nothing they could not already see in the link.
    """
    body = md.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(body):
        if not line.startswith("# "):
            continue
        for follow in body[i + 1:]:
            text = follow.strip()
            # Skip structure, not emphasis. "*" and "-" were skipped as list
            # markers, which also threw away a paragraph opening in bold: a
            # guide that leads with "**Status: shipped.** ..." lost that
            # sentence and had the fragment after it printed as its summary.
            # A list marker is the character followed by a space.
            if not text or text.startswith(("#", "|", "```", ">")):
                continue
            if re.match(r"^([-*+]\s|\d+\.\s)", text):
                continue
            text = re.sub(r"[`*\[\]]", "", text)
            text = re.sub(r"\(([^)]*)\)", "", text)
            cut = text.find(". ")
            if 0 < cut < 160:
                return text[:cut + 1].strip()
            return (text[:157].rstrip() + "…") if len(text) > 160 else text
        break
    return f"{_title_of(md)} — an UltraWideLock guide."


def _ordered(pages: list[Path]) -> list[tuple[str, list[Path]]]:
    """Group the guides for the sidebar, keeping every file reachable."""
    by_stem = {md.stem: md for md in pages}
    grouped, placed = [], set()
    for cap, stems in DOC_GROUPS:
        members = [by_stem[s] for s in stems if s in by_stem]
        placed.update(md.stem for md in members)
        if members:
            grouped.append((cap, members))
    rest = [md for md in pages if md.stem not in placed]
    if rest:
        grouped.append(("More", rest))
    return grouped


def build_docs() -> list[Path]:
    """Render docs/*.md into dist/docs/ with a sidebar, a TOC and search."""
    if not DOCS.is_dir():
        print("build: no docs/ directory, skipping the guides")
        return []
    sys.path.insert(0, str(WEB / "site"))
    import markdown                                            # noqa: PLC0415

    pages = sorted(DOCS.glob("*.md"))
    if not pages:
        return []
    out_dir = DIST / "docs"
    out_dir.mkdir(parents=True, exist_ok=True)
    tpl = (WEB / "site" / "docs.tpl.html").read_text()

    titles = {md: _title_of(md) for md in pages}
    summaries = {md: _summary_of(md) for md in pages}
    groups = _ordered(pages)
    # Reading order, flattened: what prev/next walks.
    flat = [md for _cap, members in groups for md in members]

    def tree_for(current: str) -> str:
        rows = ['<div class="tree-cap">Guides</div>',
                f'<a class="doclink{" on" if not current else ""}" '
                f'href="index.html">All guides</a>']
        for cap, members in groups:
            rows.append(f'<div class="tree-cap">{html_escape(cap)}</div>')
            for md in members:
                on = " on" if md.stem == current else ""
                rows.append(f'<a class="doclink{on}" href="{md.stem}.html">'
                            f'{html_escape(titles[md])}</a>')
        return "".join(rows)

    def toc_for(toc: list) -> str:
        """The on-this-page rail.

        markdown.render() has always returned this and build.py has always
        thrown it away, so every guide shipped without one. Only h2/h3 are
        listed: the h1 is the page title, and h4 and below are too fine to
        navigate by.
        """
        rows = [f'<a class="toc-link lv{lvl}" href="#{anchor}">'
                f'{html_escape(title)}</a>'
                for lvl, title, anchor in toc if 2 <= lvl <= 3]
        if len(rows) < 2:
            return ""      # a one-entry contents list is furniture, not a tool
        return ('<aside class="toc-rail"><div class="toc-in">'
                '<div class="toc-cap">On this page</div>'
                f'<nav aria-label="On this page">{"".join(rows)}</nav>'
                "</div></aside>")

    def pager_for(md: Path) -> str:
        i = flat.index(md)
        parts = []
        if i > 0:
            prev = flat[i - 1]
            parts.append(f'<a class="prev" href="{prev.stem}.html">'
                         f'<span class="dir">Previous</span>'
                         f'<span class="to">{html_escape(titles[prev])}</span></a>')
        if i + 1 < len(flat):
            nxt = flat[i + 1]
            parts.append(f'<a class="next" href="{nxt.stem}.html">'
                         f'<span class="dir">Next</span>'
                         f'<span class="to">{html_escape(titles[nxt])}</span></a>')
        return f'<nav class="pager" aria-label="Guides">{"".join(parts)}</nav>' \
            if parts else ""

    def render(md: Path | None, title: str, desc: str, slug: str,
               body: str, toc_html: str, pager: str) -> str:
        crumb = (f'<a href="../index.html">home</a><span class="sep">/</span>'
                 f'<a href="index.html">guides</a>'
                 + (f'<span class="sep">/</span><b>{html_escape(title)}</b>'
                    if md is not None else ""))
        return (tpl.replace("@@HEAD@@",
                            head(f"{title} — UltraWideLock", desc, 1,
                                 f"docs/{slug}.html"))
                   .replace("@@NAV@@", nav(1, "docs/index.html"))
                   .replace("@@CRUMB@@", crumb)
                   .replace("@@TREE@@", tree_for(slug if md is not None else ""))
                   .replace("@@TOC@@", toc_html)
                   .replace("@@PAGER@@", pager)
                   .replace("@@FOOTER@@", footer(1))
                   .replace("@@BODY@@", body))

    written, index = [], []
    for md in pages:
        body, toc = markdown.render(md.read_text(encoding="utf-8"))
        dest = out_dir / f"{md.stem}.html"
        dest.write_text(render(md, titles[md], summaries[md], md.stem, body,
                               toc_for(toc), pager_for(md)), encoding="utf-8")
        written.append(dest)

        index.append({"t": titles[md], "u": f"{md.stem}.html",
                      "k": "guide", "c": summaries[md]})
        for lvl, title, anchor in toc:
            if lvl == 1:
                continue
            index.append({"t": title, "u": f"{md.stem}.html#{anchor}",
                          "k": "section", "c": titles[md]})

    cards = []
    for cap, members in groups:
        rows = "".join(
            f'<li><a href="{md.stem}.html">'
            f'<span class="row-name">{html_escape(titles[md])}</span>'
            f'<span class="row-desc">{html_escape(summaries[md])}</span></a></li>'
            for md in members)
        cards.append(f'<h2>{html_escape(cap)}</h2><ul class="rows">{rows}</ul>')

    dest = out_dir / "index.html"
    dest.write_text(render(
        None, "Guides",
        "Bring-up, porting and bench notes for the boards this firmware runs on.",
        "index",
        '<span class="eyebrow">Documentation</span><h1>Guides</h1>'
        '<p class="lede">Bring-up, porting and bench notes for the boards this '
        "firmware runs on. Every one of them is a file in <code>docs/</code>, "
        "readable on GitHub as well as here.</p>" + "".join(cards),
        "", ""), encoding="utf-8")
    written.append(dest)

    search = out_dir / "search.json"
    search.write_text(json.dumps(index, separators=(",", ":")),
                      encoding="utf-8")
    written.append(search)

    print(f"build: {len(pages)} guide(s) -> docs/  "
          f"({len(index)} search entries)")
    return written


# Where `make esp-release` leaves the merged single-image binaries. Each is
# bootloader + partition table + app fused at offset 0, which is what the
# flasher writes.
ESP_CHIPS = ("esp32s3", "esp32c5", "esp32c6")


def stage_firmware() -> list[Path]:
    """Copy the ESP32 images the flasher offers, and check its manifest.

    The manifest names three .bin files. Nothing verified they existed, so the
    page shipped a button that 404'd: the link gate only walks HTML href/src,
    not JSON. Now a missing image is a build-time answer rather than a
    runtime failure for whoever clicked it.
    """
    import json                                                # noqa: PLC0415

    flash_dir = DIST / "flash"
    manifest = flash_dir / "manifest.json"
    if not manifest.is_file():
        return []

    wanted = []
    for build in json.loads(manifest.read_text()).get("builds", []):
        for part in build.get("parts", []):
            wanted.append((build.get("chipFamily", "?"), part["path"]))

    staged, missing = [], []
    for family, name in wanted:
        src = ROOT / "build" / f"esp32-matter-lock-{_chip_of(name)}" / name
        if src.is_file():
            dest = flash_dir / name
            shutil.copy2(src, dest)
            staged.append(dest)
        else:
            missing.append((family, name))

    if staged:
        total = sum(f.stat().st_size for f in staged)
        print(f"build: {len(staged)} firmware image(s) -> flash/  "
              f"({total // 1024} KB)")
    if missing:
        print(f"build: {len(missing)} firmware image(s) absent, the flasher "
              f"will say so (make esp-release)")
        _mark_flasher_unbuilt(flash_dir / "index.html", missing)
    return staged


def stage_ota() -> list[Path]:
    """Copy the over-the-air updates and the index the FOTA panel reads.

    `make ota-fan` leaves both in build/release/ota. Absent is the NORMAL
    state, not a failure: a clone that has never cut a release has nothing to
    publish, and CI's docs-check runs in exactly that state. So this stays
    quiet about missing artifacts and lets the page degrade at runtime -- it
    fetches the index, does not find one, and says no updates are published.

    Deliberately unlike stage_firmware(), which marks the page when its images
    are missing. That one has a button that would 404; this one already asks
    the network for the index before it offers anything, so there is no dead
    control to warn about.
    """
    src_root = ROOT / "build" / "release" / "ota"
    index = src_root / "ota-index.json"
    if not index.is_file():
        return []

    out_root = DIST / "flash" / "ota"
    if out_root.exists():
        shutil.rmtree(out_root)
    shutil.copytree(src_root, out_root)

    staged = [p for p in out_root.rglob("*") if p.is_file()]
    total = sum(p.stat().st_size for p in staged)

    # Counted from the INDEX rather than from the file list. Every delta is two
    # files (a .bin and the .zip phone tooling expects) and a recovery image is
    # two more (the image and its sidecar), so counting files reported twice
    # what was actually published and would now report four times.
    try:
        idx = json.loads(index.read_text())
        targets = idx.get("targets", {})
        updates = sum(len(t.get("updates", {})) or (1 if "image" in t else 0)
                      for t in targets.values())
        wholes = sum(1 for t in targets.values() if "recovery" in t)
    except (ValueError, OSError):
        updates, wholes = len(staged) - 1, 0

    extra = f" + {wholes} whole image" if wholes else ""
    print(f"build: {updates} over-the-air update(s){extra} -> flash/ota/  "
          f"({total // 1024} KB)")
    return staged


def _chip_of(binary_name: str) -> str:
    for chip in ESP_CHIPS:
        if binary_name.endswith(f"-{chip}.bin"):
            return chip
    return binary_name.rsplit("-", 1)[-1].removesuffix(".bin")


def _mark_flasher_unbuilt(page: Path, missing: list) -> None:
    """Say plainly on the page that this build carries no images."""
    if not page.is_file():
        return
    names = ", ".join(family for family, _ in missing)
    note = ('<div class="callout callout-warn"><span class="ico">warn</span>'
            "<div><p><strong>No firmware in this build.</strong> Images for "
            f"{names} were not staged, so the install button has nothing to "
            "write. Build them with <code>make esp-release</code>, or use a "
            "published release.</p></div></div>")
    text = page.read_text()
    if "No firmware in this build" in text:
        return
    marker = '<div class="flashrow">'
    if marker in text:
        page.write_text(text.replace(marker, note + marker, 1))


DESIGN = WEB / "assets" / "design"


def copy_trees() -> list[Path]:
    written: list[Path] = []
    for src, rel in TREES.items():
        if not src.is_dir():
            raise SystemExit(f"build: missing source tree {src}")
        for path in sorted(src.rglob("*")):
            if not path.is_file() or path.suffix in NOT_PUBLISHED:
                continue
            # Build inputs that live beside the pages they produce.
            if path.name.startswith("_ref-") or path.name.endswith(".tpl.html"):
                continue
            # Under the design system only the fonts are shipped as files. The
            # stylesheets and scripts are inputs to bundle_css()/bundle_js(),
            # and copying them too would publish both halves of every rule --
            # dead bytes, and two sources of truth for whoever edits next.
            if src == DESIGN and path.parent.name != "fonts":
                continue
            out = DIST / rel / path.relative_to(src)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, out)
            written.append(out)
    return written


# Repository assets the site shows. The social preview is the og:image: link
# previews are the one place the site is seen before it is visited, and a
# missing one renders as a bare grey card in every chat app. The two captures
# are the landing page's proof section, real phone screens recorded against
# the lock on the bench, one per theme.
SITE_ASSETS = ("social-preview.png", "grid-demo-dark.webp", "grid-demo-light.webp")


def stage_assets() -> list[Path]:
    """Copy the repository assets the pages reference into dist/assets/."""
    written = []
    for name in SITE_ASSETS:
        src = ROOT / "assets" / name
        if not src.is_file():
            print(f"build: assets/{name} absent, the page that shows it will 404")
            continue
        dest = DIST / "assets" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        written.append(dest)
    return written


LINK_RE = re.compile(r'(?:href|src)="([^"#][^"]*)"')


def check_links(pages: list[Path], have_twin: bool, have_graph: bool) -> list[str]:
    """Every relative href/src in the output must resolve to a real file.

    Two exceptions, each only when the optional tool behind it was absent:
    twin.js without emscripten, and the graph page without graphify. Both
    pages are worth publishing regardless, and neither tool is a build
    requirement, so a missing one must not fail the gate.
    """
    dead: list[str] = []
    for page in pages:
        if page.suffix != ".html":
            continue
        text = page.read_text(encoding="utf-8", errors="replace")
        for target in LINK_RE.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "data:", "//",
                                  "about:", "blob:", "javascript:")):
                continue
            resolved = (page.parent / target.split("?")[0].split("#")[0]).resolve()
            if resolved.is_dir():
                resolved = resolved / "index.html"
            if not resolved.exists():
                if not have_twin and resolved.name == "twin.js":
                    continue
                if not have_graph and resolved.parent.name == "graph":
                    continue
                dead.append(f"{page.relative_to(DIST)} -> {target}")
    return dead


LANDING_TITLE = "UltraWideLock — NFC and UWB smart lock firmware"
LANDING_DESC = ("Portable firmware for NFC and UWB smart locks. "
                "Implements Aliro, the CSA's door-lock credential standard, "
                "on nRF52833, nRF5340 and ESP32.")


def build_landing() -> Path:
    """Render the landing page around the shared chrome."""
    tpl = (WEB / "site" / "index.tpl.html").read_text(encoding="utf-8")
    page = (tpl.replace("@@HEAD@@",
                        head(LANDING_TITLE, LANDING_DESC, 0, "index.html"))
               .replace("@@NAV@@", nav(0))
               .replace("@@FOOTER@@", footer(0)))
    dest = DIST / "index.html"
    dest.write_text(page, encoding="utf-8")
    return dest


# The tool pages keep their own <head> -- the flasher's CSP and the twin's
# inline canvas styles are page-specific and do not belong in a shared partial
# -- but they share the bar, so the wordmark, the theme toggle and the way back
# are identical everywhere instead of three hand-written near-copies.
TOOLBAR_RE = re.compile(r"@@TOOLBAR:([^@]*)@@")

GH_MARK = ('<svg viewBox="0 0 16 16" width="15" height="15" fill="currentColor" '
           'aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 '
           '5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49'
           '-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 '
           '1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2'
           '-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 '
           '.67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 '
           '2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75'
           '-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55'
           '.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>')


def tool_bar(crumb: str, depth: int) -> str:
    rel = rel_to_root(depth)
    return (f'<header class="topbar toolbar">'
            f'<a class="wordmark" href="{rel}index.html">UltraWideLock</a>'
            f'<span class="crumb-sep" aria-hidden="true">/</span>'
            f'<span class="crumb">{html_escape(crumb)}</span>'
            f'<div class="spacer"></div>'
            f'<a class="navlink hide-narrow" href="{rel}docs/index.html">Docs</a>'
            f'<a class="gh-chip" href="{GITHUB}" data-ext '
            f'aria-label="ultrawidelock on GitHub">{GH_MARK}'
            f'<span class="hide-narrow">ultrawidelock</span></a>'
            f'{THEME_BTN}</header>')


def inject_shell(pages: list[Path]) -> None:
    """Substitute the shared chrome into pages that asked for it."""
    for page in pages:
        if page.suffix != ".html":
            continue
        text = page.read_text(encoding="utf-8")
        if "@@" not in text:
            continue
        depth = len(page.relative_to(DIST).parts) - 1
        text = TOOLBAR_RE.sub(
            lambda m: tool_bar(m.group(1), depth), text)
        text = (text.replace("@@NAV@@", nav(depth))
                    .replace("@@FOOTER@@", footer(depth))
                    .replace("@@SITEJS@@",
                             f'<script src="{rel_to_root(depth)}'
                             f'assets/design/site.js" defer></script>'))
        page.write_text(text, encoding="utf-8")


# The gates that keep the pages honest about the firmware. Each is a standalone
# script that exits nonzero on drift; --check runs all three.
#
# They existed and nothing ran them. check_constants.py in particular could
# never have passed -- it resolved its citations against web/ rather than the
# repository root, so every file it tried to open was missing -- and because no
# target invoked it, the twin's PRED_GRACE_MS sat at half the firmware's value
# without anyone finding out. A gate nobody runs is a comment.
GATES = (
    ("twin constants", WEB / "twin" / "check_constants.py"),
    ("hero constants", WEB / "site" / "check_hero_constants.py"),
    ("flasher setup codes", WEB / "flasher" / "check_codes.py"),
)


def run_gates() -> list[str]:
    """Run each drift gate. Returns the names of the ones that failed."""
    failed = []
    for name, script in GATES:
        if not script.is_file():
            continue
        result = subprocess.run([sys.executable, str(script)],
                                capture_output=True, text=True)
        if result.returncode == 0:
            print(f"build: gate ok  {name}")
            continue
        failed.append(name)
        print(f"build: gate FAILED  {name}", file=sys.stderr)
        for line in (result.stdout + result.stderr).strip().splitlines():
            print(f"  {line}", file=sys.stderr)
    return failed


def main() -> int:
    global HAVE_GRAPH, REFRESH_GRAPH
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="fail on any dead internal link")
    ap.add_argument("--refresh-graph", action="store_true",
                    help="rewrite web/graph/subsystems.json from graphify-out/")
    args = ap.parse_args()
    REFRESH_GRAPH = args.refresh_graph

    clean()
    # Decided before any page is rendered, because the nav has to know whether
    # to carry a Graph link at all. Either data source will do.
    HAVE_GRAPH = ((ROOT / "graphify-out" / "graph.json").is_file()
                  or (WEB / "graph" / "subsystems.json").is_file())

    have_twin = build_twin_wasm()
    written = copy_trees()
    written.append(bundle_css())
    written += bundle_js()
    written += stage_assets()
    written.append(build_landing())
    written += build_docs()
    written += stage_firmware()
    written += stage_ota()
    graph_page = build_graph()
    if graph_page:
        written.append(graph_page)

    inject_shell(written)
    written += emit_meta([str(p.relative_to(DIST)) for p in written
                          if p.suffix == ".html" and p.name != "404.html"])
    print(f"build: {len(written)} file(s) -> {DIST.relative_to(ROOT)}")

    dead = check_links(written, have_twin, HAVE_GRAPH)
    for entry in dead:
        print(f"build: dead link  {entry}", file=sys.stderr)
    if not args.check:
        return 0

    failed = run_gates()
    if dead:
        print(f"build: {len(dead)} dead link(s)", file=sys.stderr)
    else:
        print("build: no dead internal links")
    if dead or failed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
