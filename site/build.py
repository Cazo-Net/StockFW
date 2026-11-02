#!/usr/bin/env python3
"""Build the StockFW website and documentation.

    python3 site/build.py           write the HTML pages into site/public/
    python3 site/build.py --check   fail if site/public/ is out of date

Standard library only (Python 3.8 or later), no network.

Sources live in site/src/:
    layouts/   the page frame (base.html) and its parts
    pages/     one file per page: a front-matter block, then HTML

Hand-written assets (CSS, JavaScript, fonts, images, screenshots) live
directly in site/public/assets/.  Everything else in site/public/ is
written by this script, plus assets/js/search-index.js.

The build fails, and writes nothing, when a page links to a file or an
anchor that does not exist, or uses a shortcode it does not know.
"""

import html
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
PUBLIC = HERE / "public"
LAYOUTS = SRC / "layouts"
PAGES = SRC / "pages"

CONFIG = {
    "version": "1.0.6",          # what the docs describe (main)
    "next": "1.0.7",             # what is being built
    "release": "1.0.5",          # the newest published GitHub release
    "repo": "https://github.com/Cazo-Net/StockFW",
    "site_name": "StockFW",
}

# The documentation rail, in reading order.  A docs page names its
# section in front matter; pages inside a section sort by `order`.
SECTIONS = [
    "Get started",
    "Using the app",
    "Protection",
    "Command line",
    "Reference",
]

SEARCH_INDEX = "assets/js/search-index.js"


class BuildError(Exception):
    pass


# ----------------------------------------------------------- reading

FRONT = re.compile(r"\A---\n(.*?)\n---\n", re.S)


def read_page(path):
    text = path.read_text(encoding="utf-8")
    m = FRONT.match(text)
    if not m:
        raise BuildError(f"{path}: missing front matter (--- ... ---)")
    meta = {}
    for line in m.group(1).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if not sep:
            raise BuildError(f"{path}: bad front-matter line {line!r}")
        meta[key.strip()] = value.strip()
    rel = path.relative_to(PAGES).as_posix()
    meta.setdefault("layout", "docs" if rel.startswith("docs/") else "page")
    for required in ("title", "description"):
        if required not in meta:
            raise BuildError(f"{path}: front matter needs `{required}`")
    if meta["layout"] == "docs":
        if meta.get("section") not in SECTIONS:
            raise BuildError(f"{path}: section must be one of {SECTIONS}")
        meta["order"] = int(meta.get("order", "100"))
    return {"rel": rel, "meta": meta, "body": text[m.end():], "src": path}


def layout(name):
    path = LAYOUTS / f"{name}.html"
    if not path.exists():
        raise BuildError(f"no layout {name}")
    return path.read_text(encoding="utf-8")


# ------------------------------------------------------- shortcodes

EV_LABELS = {
    "verified": ("Verified", ""),
    "measured": ("Measured", ""),
    "built": ("Built", "for 1.0.7"),
    "soon": ("In progress", "for 1.0.7"),
    "planned": ("Planned", ""),
    "gap": ("Known gap", ""),
}
EV_TITLES = {
    "verified": "An automated test in the StockFW repository proves this claim.",
    "measured": "A number from an experiment that was actually run.",
    "built": "Done on the 1.0.7 development branch; ships with 1.0.7.",
    "soon": "Being built for 1.0.7; details may still change.",
    "planned": "Intended, not built yet.",
    "gap": "A limit StockFW has today, stated so it is not mistaken for a feature.",
}
PLATFORMS = {"win": "Windows", "linux": "Linux", "both": "Windows and Linux"}
SHORTCODE = re.compile(r"\[\[([a-z]+)(?::([^\]]*))?\]\]")


def shortcodes(text, where):
    def sub(m):
        kind, arg = m.group(1), (m.group(2) or "").strip()
        if kind in EV_LABELS:
            label, default = EV_LABELS[kind]
            detail = arg or default
            inner = f"<b>{label}</b>"
            if detail:
                inner += " " + detail
            return (f'<span class="ev ev-{kind}" title="{html.escape(EV_TITLES[kind])}">'
                    f"{inner}</span>")
        if kind in PLATFORMS:
            return f'<span class="plat">{PLATFORMS[kind]}</span>'
        if kind == "shot":
            return shot(arg, where)
        raise BuildError(f"{where}: unknown shortcode [[{kind}]]")
    return SHORTCODE.sub(sub, text)


def webp_size(path):
    """(width, height) of a WebP file, read from its header."""
    data = path.read_bytes()[:40]
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise BuildError(f"{path}: not a WebP file")
    chunk = data[12:16]
    if chunk == b"VP8X":
        w = 1 + int.from_bytes(data[24:27], "little")
        h = 1 + int.from_bytes(data[27:30], "little")
    elif chunk == b"VP8 ":
        w, h = struct.unpack("<HH", data[26:30])
        w, h = w & 0x3FFF, h & 0x3FFF
    elif chunk == b"VP8L":
        bits = int.from_bytes(data[21:25], "little")
        w, h = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    else:
        raise BuildError(f"{path}: unknown WebP chunk {chunk!r}")
    return w, h


def shot(arg, where):
    """[[shot:name|alt text|caption]] -- a screenshot from assets/screens.
    Screenshots are taken at twice their display size."""
    parts = [p.strip() for p in arg.split("|")]
    if len(parts) < 2:
        raise BuildError(f"{where}: [[shot:name|alt|caption]] needs alt text")
    name, alt = parts[0], parts[1]
    caption = parts[2] if len(parts) > 2 else ""
    path = PUBLIC / "assets" / "screens" / f"{name}.webp"
    if not path.exists():
        raise BuildError(f"{where}: no screenshot {path.name}")
    w, h = webp_size(path)
    cls = "shot narrow" if w <= 1400 else "shot"
    out = (f'<figure class="{cls}"><img src="{{{{root}}}}assets/screens/{name}.webp" '
           f'alt="{html.escape(alt)}" width="{w // 2}" height="{h // 2}" loading="lazy" decoding="async">')
    if caption:
        out += f"<figcaption>{caption}</figcaption>"
    return out + "</figure>"


# ------------------------------------------------------- code blocks

PRE = re.compile(r'<pre data-lang="([a-z]+)"(?: data-title="([^"]*)")?>\n?(.*?)</pre>', re.S)
PROMPTS = {"sh": "$ ", "term": "$ ", "ps": "PS> "}


def code_blocks(text):
    def sub(m):
        lang, title, body = m.group(1), m.group(2), m.group(3).rstrip("\n")
        if "<" in body.replace("<span", "").replace("</span>", "").replace("<b>", "").replace("</b>", ""):
            # Code must arrive escaped; a raw "<" means a typo.
            if re.search(r"<(?!/?span|/?b>)", body):
                raise BuildError(f"unescaped '<' in a {lang} code block: {body[:60]!r}")
        prompt = PROMPTS.get(lang)
        lines = []
        for line in body.split("\n"):
            if prompt and line.startswith(prompt):
                cmd = line[len(prompt):]
                comment = ""
                if "  # " in cmd:
                    cmd, _, rest = cmd.partition("  # ")
                    comment = f'  <span class="c"># {rest}</span>'
                lines.append(f'<span class="p">{prompt}</span><span class="cmd">{cmd}</span>{comment}')
            elif lang in ("sh", "ps", "conf") and line.lstrip().startswith("#"):
                lines.append(f'<span class="c">{line}</span>')
            else:
                lines.append(line)
        label = title or {"sh": "Terminal", "term": "Terminal", "ps": "PowerShell",
                          "csv": "Policy file", "conf": "File", "text": "Output",
                          "json": "JSON"}.get(lang, lang)
        copy = "commands" if prompt else "all"
        return (f'<div class="code" data-copy="{copy}"><div class="code-head"><span>{label}</span>'
                f'<button class="copy-btn" type="button" hidden>Copy</button></div>'
                f'<pre><code>{chr(10).join(lines)}</code></pre></div>')
    return PRE.sub(sub, text)


# --------------------------------------------------------- headings

HEADING = re.compile(r"<h([23])(\s[^>]*)?>(.*?)</h\1>", re.S)
TAG = re.compile(r"<[^>]+>")


def plain(fragment):
    return html.unescape(TAG.sub("", fragment)).strip()


def slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "section"


def headings(text, where):
    """Give every h2/h3 an id and a link to itself; return the list."""
    found, seen = [], set()

    def sub(m):
        level, attrs, inner = m.group(1), m.group(2) or "", m.group(3)
        idm = re.search(r'\sid="([^"]+)"', attrs)
        hid = idm.group(1) if idm else slugify(plain(inner))
        base, n = hid, 2
        while hid in seen:
            hid, n = f"{base}-{n}", n + 1
        seen.add(hid)
        if not idm:
            attrs += f' id="{hid}"'
        found.append((int(level), plain(inner), hid))
        return (f'<h{level}{attrs}>{inner}<a class="anchor" href="#{hid}" '
                f'aria-label="Link to this section">#</a></h{level}>')
    return HEADING.sub(sub, text), found


# --------------------------------------------------------- assembly

def fill(template, values, where):
    def sub(m):
        key = m.group(1)
        if key not in values:
            raise BuildError(f"{where}: template needs {{{{{key}}}}}")
        return values[key]
    return re.sub(r"\{\{([a-z_]+)\}\}", sub, template)


def partials(template):
    return re.sub(r"\{\{> ([a-z]+)\}\}", lambda m: layout(m.group(1)), template)


def docs_nav(pages, current, root):
    out = []
    for section in SECTIONS:
        items = [p for p in pages if p["meta"].get("section") == section]
        if not items:
            continue
        out.append(f"\t\t<h2>{section}</h2>\n\t\t<ul>")
        for p in items:
            m = p["meta"]
            cur = ' aria-current="page"' if p is current else ""
            tag = f'<span class="tag">{m["tag"]}</span>' if m.get("tag") else ""
            label = html.escape(m.get("nav", m["title"]))
            out.append(f'\t\t\t<li><a href="{root}{p["rel"]}"{cur}><span>{label}</span>{tag}</a></li>')
        out.append("\t\t</ul>")
    return "\n".join(out)


def toc(found):
    items = [h for h in found if h[0] in (2, 3)]
    if len(items) < 2:
        return ""
    lis = "\n".join(f'\t\t\t<li class="lvl{lvl}"><a href="#{hid}">{html.escape(text)}</a></li>'
                    for lvl, text, hid in items)
    return f"\t\t<h2>On this page</h2>\n\t\t<ul>\n{lis}\n\t\t</ul>"


def pager(order, i, root):
    prev = order[i - 1] if i > 0 else None
    nxt = order[i + 1] if i + 1 < len(order) else None
    parts = []
    if prev:
        parts.append(f'<a class="prev" href="{root}{prev["rel"]}"><span>Previous</span>'
                     f'<strong>{html.escape(prev["meta"]["title"])}</strong></a>')
    if nxt:
        parts.append(f'<a class="next" href="{root}{nxt["rel"]}"><span>Next</span>'
                     f'<strong>{html.escape(nxt["meta"]["title"])}</strong></a>')
    return '\t\t\t<nav class="pager" aria-label="Pages">' + "".join(parts) + "</nav>"


def render(page, docs_order):
    meta, rel = page["meta"], page["rel"]
    depth = rel.count("/")
    root = "../" * depth if depth else "./"
    where = f"src/pages/{rel}"

    body = shortcodes(page["body"], where)
    body = code_blocks(body)
    found = []
    if meta["layout"] in ("docs", "page"):
        body, found = headings(body, where)

    common = {
        "root": root,
        "title": html.escape(meta["title"]),
        "description": html.escape(meta["description"]),
        "version": CONFIG["version"],
        "next": CONFIG["next"],
        "release": CONFIG["release"],
        "repo": CONFIG["repo"],
    }
    body = fill(body, common, where)

    if meta["layout"] == "docs":
        i = docs_order.index(page)
        main = fill(layout("docs"), dict(common, **{
            "docs_nav": docs_nav(docs_order, page, root),
            "section": html.escape(meta["section"]),
            "content": body,
            "pager": pager(docs_order, i, root),
            "toc": toc(found),
            "edit_url": f'{CONFIG["repo"]}/blob/main/site/src/pages/{rel}',
        }), where)
        css = f'<link rel="stylesheet" href="{root}assets/css/docs.css">'
        js = ""
    elif meta["layout"] == "page":
        main = fill(layout("page"), dict(common, **{
            "eyebrow": html.escape(meta.get("eyebrow", "StockFW")),
            "content": body,
        }), where)
        css, js = "", ""
    elif meta["layout"] == "home":
        main = body
        css = f'<link rel="stylesheet" href="{root}assets/css/home.css">'
        js = f'<script src="{root}assets/js/home.js" defer></script>'
    else:
        raise BuildError(f"{where}: unknown layout {meta['layout']}")

    section_key = rel.split("/")[0].replace(".html", "")
    current = {f"cur_{k}": "" for k in ("home", "docs", "download", "changelog")}
    key = {"docs": "cur_docs", "download": "cur_download", "changelog": "cur_changelog"}.get(section_key)
    if key:
        current[key] = ' aria-current="page"'

    title_full = meta["title"] if rel == "index.html" else f'{meta["title"]} · StockFW'
    page_html = fill(partials(layout("base")), dict(common, **current, **{
        "title_full": html.escape(meta.get("head_title", title_full)),
        "main": main,
        "extra_css": css,
        "extra_js": js,
        "body_class": f'layout-{meta["layout"]}',
    }), where)
    return page_html, found, body


def search_entry(page, found, body):
    text = re.sub(r"\s+", " ", plain(re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", body, flags=re.S)))
    return {
        "t": page["meta"]["title"],
        "u": page["rel"],
        "s": page["meta"].get("section", page["meta"].get("eyebrow", "StockFW")),
        "h": [[t, hid] for lvl, t, hid in found],
        "x": text[:8000],
    }


# ------------------------------------------------------- link check

ATTR = re.compile(r'\s(?:href|src)="([^"]+)"')
IDS = re.compile(r'\sid="([^"]+)"')


def check_links(outputs):
    ids = {rel: set(IDS.findall(text)) for rel, text in outputs.items() if rel.endswith(".html")}
    errors = []
    for rel, text in outputs.items():
        if not rel.endswith(".html"):
            continue
        base = Path(rel).parent
        for url in ATTR.findall(text):
            if re.match(r"^(https?:|mailto:|data:)", url):
                continue
            path, _, frag = url.partition("#")
            if path:
                target = (base / path).as_posix()
                # normalise ../
                parts = []
                for seg in target.split("/"):
                    if seg == "..":
                        if parts:
                            parts.pop()
                    elif seg not in ("", "."):
                        parts.append(seg)
                target = "/".join(parts)
            else:
                target = rel
            if target not in outputs and not (PUBLIC / target).is_file():
                errors.append(f"{rel}: broken link {url}")
                continue
            if frag and target.endswith(".html"):
                if frag not in ids.get(target, set()):
                    errors.append(f"{rel}: no #{frag} in {target}")
    if errors:
        raise BuildError("\n".join(errors))


# ------------------------------------------------------------- main

def build():
    pages = [read_page(p) for p in sorted(PAGES.rglob("*.html"))]
    docs = [p for p in pages if p["meta"]["layout"] == "docs"]
    docs.sort(key=lambda p: (SECTIONS.index(p["meta"]["section"]), p["meta"]["order"], p["rel"]))

    outputs, index = {}, []
    for page in pages:
        page_html, found, body = render(page, docs)
        outputs[page["rel"]] = page_html
        if page["meta"]["layout"] != "home" and page["meta"].get("search", "yes") != "no":
            index.append(search_entry(page, found, body))
    index.sort(key=lambda e: (e["u"] != "docs/index.html", not e["u"].startswith("docs/"), e["u"]))
    outputs[SEARCH_INDEX] = ("/* Generated by site/build.py -- do not edit. */\nwindow.SFW_SEARCH = "
                             + json.dumps(index, ensure_ascii=False, separators=(",", ":")) + ";\n")
    check_links(outputs)
    return outputs


def generated_on_disk():
    found = {p.relative_to(PUBLIC).as_posix() for p in PUBLIC.rglob("*.html")}
    if (PUBLIC / SEARCH_INDEX).exists():
        found.add(SEARCH_INDEX)
    return found


def main(argv):
    check = "--check" in argv
    try:
        outputs = build()
    except BuildError as e:
        print(f"build failed:\n{e}", file=sys.stderr)
        return 1

    if check:
        stale = []
        for rel, text in outputs.items():
            path = PUBLIC / rel
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(rel)
        extra = sorted(generated_on_disk() - set(outputs))
        if stale or extra:
            for rel in stale:
                print(f"out of date: site/public/{rel}", file=sys.stderr)
            for rel in extra:
                print(f"no source for: site/public/{rel}", file=sys.stderr)
            print("run: python3 site/build.py", file=sys.stderr)
            return 1
        print(f"site/public is up to date ({len(outputs)} files)")
        return 0

    for rel in sorted(generated_on_disk() - set(outputs)):
        (PUBLIC / rel).unlink()
        print(f"removed site/public/{rel}")
    for rel, text in outputs.items():
        path = PUBLIC / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
    print(f"wrote site/public ({len(outputs)} files, links checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
