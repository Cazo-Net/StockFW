# The StockFW website and documentation

Everything under `site/` is the public website: the home page, the
download and changelog pages, and the documentation.  It is a static
site, built by one Python script with no dependencies beyond Python 3.

```
python3 site/build.py           # write site/public/
python3 site/build.py --check   # CI: fail if site/public/ is out of date
```

## Layout

| Path | What |
|---|---|
| `src/pages/*.html` | One file per page: a front-matter block (`title`, `description`, `section`, `order`), then the page's HTML. |
| `src/pages/docs/*.html` | The documentation.  `section` places a page in the rail; `order` sorts it within the section. |
| `src/layouts/` | The page frame (`base.html`) and its parts (header, footer, search dialog, docs frame, plain-page frame). |
| `public/assets/` | Hand-written assets: CSS, JavaScript, self-hosted fonts (OFL), the logo, screenshots. |
| `public/*.html`, `public/docs/*.html`, `public/assets/js/search-index.js` | Written by `build.py`.  Do not edit by hand. |

## Writing a page

The HTML is plain.  A few shortcodes expand at build time:

| Shortcode | Renders |
|---|---|
| `[[verified:test name]]` | A green "Verified" stamp naming the test that proves the claim. |
| `[[measured:what]]` | A "Measured" stamp for a number from an experiment. |
| `[[gap]]` | A known limit, stated so it is not mistaken for a feature. |
| `[[win]]`, `[[linux]]`, `[[both]]` | A platform badge. |
| `[[shot:name\|alt text\|caption]]` | A screenshot from `public/assets/screens/name.webp`, with its real dimensions. |

Code blocks are `<pre data-lang="sh" data-title="optional title">`.
A `<dl>` whose terms are all short (28 characters or fewer) is shown in
two columns, term beside definition; a list with a longer term stacks
each definition under its term.  A path in a table's `<code>` gets a
soft break after each slash, backslash and comma, so it wraps instead of
squeezing the other columns.
`{{root}}` is the relative path to the site root (so links work from
`docs/`), and `{{release}}`, `{{version}}` and `{{repo}}`
come from `CONFIG` at the top of `build.py`.

The build fails, and writes nothing, when a page links to a file or an
anchor that does not exist, or uses a shortcode it does not know.
Headings get ids from their text, so `<h2>Apply, step by step</h2>` is
`#apply-step-by-step`.

## Screenshots

The screenshots in `public/assets/screens/` were taken from the real
1.0.7 app on Linux, in a staged network namespace with a scanner on the
outside and services on the inside, under Xvfb at `GDK_SCALE=2`, then
converted to WebP.  Retake them when a page changes; the captions say
what the traffic was.

## Releasing

Bump `CONFIG["release"]` (the newest GitHub release), `CONFIG["version"]`
(what the docs describe) and `CONFIG["next"]` in `build.py`, update
`src/pages/changelog.html` and `download.html`, rebuild, commit
`public/`.  The site is self-contained and can be served from any
static host, including GitHub Pages pointed at `site/public/`.
