"""Shared self-contained HTML design system for SafeAI outputs.

Every report and registry view is a single portable HTML file: all CSS
and a small amount of dependency-free JavaScript are embedded, with no
external assets, network requests, fonts, or tracking. Content is always
HTML-escaped at the call site via :func:`html.escape` on user data.

The page template provides a sticky header (title + dark-mode toggle),
a responsive card grid, severity badges, sortable/searchable tables,
an SVG risk gauge, and print-friendly styles. ``data-theme`` on the
``<html>`` element switches the palette; the choice is remembered in
``localStorage``.

.. note::

   All visual-only helpers live here so the scan report
   (``safeai.report.html``) and the registry views
   (``safeai.report.registry_html``) look consistent without duplicating
   markup or styles.
"""

from datetime import UTC, datetime
from hashlib import md5
from html import escape

# --- Severity palette ----------------------------------------------------

SEVERITY_PALETTE = {
    "critical": ("#dc2626", "#fef2f2"),
    "high": ("#ea580c", "#fff7ed"),
    "medium": ("#ca8a04", "#fefce8"),
    "low": ("#2563eb", "#eff6ff"),
    "info": ("#0e7490", "#ecfeff"),
}


def sev_class(severity):
    """Return the CSS class for a severity label (never raises)."""
    sev = (severity or "info").lower()
    return f"sev-{sev}" if sev in SEVERITY_PALETTE else "sev-info"


def sev_badge(severity, label=None):
    """Return a severity badge ``<span>`` with the matching palette."""
    sev = (severity or "info").lower()
    fg, bg = SEVERITY_PALETTE.get(sev, SEVERITY_PALETTE["info"])
    text = escape(str(label if label is not None else sev))
    return (
        f"<span class='badge' style='color:{fg};background:{bg};border-color:{fg}33'>"
        f"{text}</span>"
    )


def freshness_badge(freshness):
    """Return a freshness indicator badge from a freshness dict.

    The freshness dict has ``label`` (fresh/aging/stale/never), ``age_days``,
    and ``color`` (CSS color). See
    :func:`safeai.kya.registry.queries.compute_freshness`.
    """
    if not freshness or freshness.get("label") in ("unknown", None):
        return "<span class='badge' style='color:#6b7280;background:#f9fafb;border-color:#6b728033'>unknown</span>"
    label = freshness["label"]
    color = freshness.get("color", "#6b7280")
    age = freshness.get("age_days")
    if age is not None:
        text = f"{label} ({age}d)"
    else:
        text = label
    return (
        f"<span class='badge' style='color:{color};background:{color}11;border-color:{color}33'>"
        f"{escape(text)}</span>"
    )


def card(body, title=None, accent=None, classes=""):
    """Return a styled card. ``accent`` is a CSS color for a top border."""
    head = f"<h3>{escape(title)}</h3>" if title else ""
    style = f"border-top:3px solid {accent};" if accent else ""
    return f"<div class='card {classes}' style='{style}'>{head}{body}</div>"


def kpi(label, value, sub=None, accent=None):
    """Return a single key-performance card (label + value)."""
    sub_html = f"<div class='muted'>{escape(sub)}</div>" if sub else ""
    return card(f"<div class='kpi-value'>{value}</div>{sub_html}", title=label, accent=accent)


def risk_gauge(score):
    """Return an SVG donut gauge for a 0-100 risk score."""
    try:
        score = max(0, min(100, round(float(score))))
    except (TypeError, ValueError):
        score = None
    if score is None:
        return "<div class='muted'>Risk score not computed</div>"
    if score >= 80:
        color = "#dc2626"
    elif score >= 50:
        color = "#ea580c"
    elif score >= 25:
        color = "#ca8a04"
    else:
        color = "#16a34a"
    circumference = 2 * 22 * 3.14159
    offset = circumference * (1 - score / 100)
    return (
        "<div class='gauge-wrap'>"
        "<svg class='gauge' viewBox='0 0 60 60' role='img' aria-label='risk score'>"
        f"<circle class='gauge-track' cx='30' cy='30' r='22'/>"
        f"<circle class='gauge-value' cx='30' cy='30' r='22' stroke='{color}' "
        f"stroke-dasharray='{circumference:.1f}' stroke-dashoffset='{offset:.1f}'/>"
        f"<text x='30' y='30' text-anchor='middle' class='gauge-text'>{score}</text>"
        "</svg>"
        "</div>"
    )


def data_table(headers, rows, empty="No records.", searchable=True, id_=None):
    """Return an accessible table with an optional client-side filter box.

    ``rows`` is a list of lists; every cell is rendered escaped.
    ``empty`` is shown when there are no rows. When ``searchable`` is
    True a search input filters rows by their combined text content.
    Table IDs are content-derived (stable across renders of the same
    report) so output stays deterministic.
    """
    table_id = id_ or f"tbl-{md5((str(headers) + str(len(rows))).encode()).hexdigest()[:8]}"
    filter_html = (
        f"<input class='filter' type='search' data-filter='{table_id}' "
        f"placeholder='Filter...' aria-label='Filter rows'/>"
        if searchable
        else ""
    )
    if not rows:
        body = f"<tr><td colspan='{len(headers)}' class='muted center'>{escape(empty)}</td></tr>"
    else:
        body = "\n".join(
            "<tr>"
            + "".join(
                f"<td>{escape(str(cell)) if cell is not None else ''}</td>" for cell in row
            )
            + "</tr>"
            for row in rows
        )
    headers_html = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    return (
        f"{filter_html}"
        f"<table id='{table_id}' data-filterable='1'>"
        f"<thead><tr>{headers_html}</tr></thead><tbody>{body}</tbody></table>"
    )


def page(title, body, generated_at=None, subtitle=None, footer=None):
    """Return a complete, self-contained HTML document string."""
    stamp = escape(generated_at or datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))
    subtitle_html = f"<span class='muted'>{escape(subtitle)}</span>" if subtitle else ""
    footer_html = (
        f"<footer class='foot muted'>{escape(footer)}</footer>" if footer else "<footer class='foot muted'>&nbsp;</footer>"
    )
    return f"""<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>{escape(title)}</title>
<style>
{_CSS}
</style>
</head>
<body>
<header class='topbar'>
  <div class='brand'>
    <span class='brand-mark' aria-hidden='true'></span>
    <span>{escape(title)}</span>
    {subtitle_html}
  </div>
  <div class='topbar-right'>
    <span class='muted stamp'>{stamp}</span>
    <button type='button' id='theme-toggle' class='btn' aria-label='Toggle dark mode'>Theme</button>
  </div>
</header>
<main class='container'>
{body}
</main>
{footer_html}
<script>
{_JS}
</script>
</body>
</html>"""


# --- Embedded CSS --------------------------------------------------------

_CSS = """
:root {
  --bg:#f3f6fb; --surface:#ffffff; --surface-2:#f8fafc;
  --ink:#1f2937; --muted:#6b7280; --line:#e5e7eb;
  --brand:#0f766e; --brand-soft:#ecfdf5; --accent:#0e7490;
  --shadow:0 1px 2px rgba(15,23,42,.06), 0 4px 12px rgba(15,23,42,.06);
}
html[data-theme="dark"] {
  --bg:#0b1220; --surface:#111a2c; --surface-2:#0f1829;
  --ink:#e5edf7; --muted:#8fa1b8; --line:#22304a;
  --brand:#2dd4bf; --brand-soft:#0b2f26; --accent:#38bdf8;
  --shadow:0 1px 2px rgba(0,0,0,.4), 0 4px 12px rgba(0,0,0,.4);
}
* { box-sizing:border-box; }
html { -webkit-text-size-adjust:100%; }
body {
  margin:0; background:var(--bg); color:var(--ink);
  font-family:'Segoe UI', system-ui, -apple-system, Roboto, Helvetica, Arial, sans-serif;
  font-size:14px; line-height:1.5;
}
.topbar {
  position:sticky; top:0; z-index:10; display:flex; align-items:center; justify-content:space-between;
  gap:12px; padding:10px 24px; background:color-mix(in srgb, var(--surface) 92%, transparent);
  backdrop-filter:blur(6px); border-bottom:1px solid var(--line);
}
.brand { display:flex; align-items:center; gap:10px; font-weight:600; font-size:15px; }
.brand-mark {
  width:10px; height:10px; border-radius:50%; background:var(--brand);
  box-shadow:0 0 0 3px color-mix(in srgb, var(--brand) 25%, transparent);
}
.brand .muted { font-weight:400; }
.topbar-right { display:flex; align-items:center; gap:12px; }
.stamp { white-space:nowrap; }
.btn {
  border:1px solid var(--line); background:var(--surface); color:var(--ink);
  border-radius:8px; padding:4px 10px; cursor:pointer; font-size:14px;
}
.btn:hover { border-color:var(--brand); }
.container { max-width:1180px; margin:0 auto; padding:20px 24px 48px; }
h1, h2, h3 { margin:0 0 10px; line-height:1.25; }
h2 { font-size:20px; margin-top:28px; padding-top:8px; border-top:1px solid var(--line); }
h3 { font-size:15px; }
a { color:var(--accent); }
.muted { color:var(--muted); font-size:13px; }
.center { text-align:center; }
.hero {
  display:grid; grid-template-columns:repeat(auto-fit, minmax(230px, 1fr)); gap:14px;
  margin:18px 0 4px;
}
.card {
  background:var(--surface); border:1px solid var(--line); border-radius:14px;
  padding:14px 16px; box-shadow:var(--shadow);
}
.card h3 { margin-bottom:8px; font-size:13px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
.kpi-value { font-size:26px; font-weight:700; color:var(--ink); }
.gauge-wrap { display:flex; justify-content:center; padding:4px 0; }
.gauge { width:120px; height:120px; }
.gauge-track { fill:none; stroke:var(--line); stroke-width:6; }
.gauge-value { fill:none; stroke-width:6; stroke-linecap:round; transform:rotate(-90deg); transform-origin:50% 50%; transition:stroke-dashoffset .6s ease; }
.gauge-text { font-size:16px; font-weight:700; fill:var(--ink); }
.badge {
  display:inline-block; padding:2px 9px; border-radius:999px;
  font-size:12px; font-weight:600; border:1px solid transparent; white-space:nowrap;
}
table { width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--line); border-radius:12px; overflow:hidden; margin:6px 0 14px; }
th, td { text-align:left; font-size:13px; padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
th { background:var(--surface-2); font-weight:600; white-space:nowrap; }
tbody tr:hover { background:color-mix(in srgb, var(--surface-2) 60%, transparent); }
tr:last-child td { border-bottom:none; }
.filter {
  width:100%; max-width:340px; margin:2px 0 8px; padding:7px 12px; font-size:13px;
  border:1px solid var(--line); border-radius:9px; background:var(--surface); color:var(--ink);
}
.filter:focus { outline:2px solid var(--brand); outline-offset:1px; }
code { background:var(--surface-2); border:1px solid var(--line); border-radius:5px; padding:1px 5px; font-size:12px; }
.kv { display:grid; grid-template-columns:max-content 1fr; gap:2px 14px; margin:4px 0; }
.kv dt { color:var(--muted); font-weight:600; }
.kv dd { margin:0; }
.grid-2 { display:grid; grid-template-columns:repeat(auto-fit, minmax(320px,1fr)); gap:14px; }
.section { margin:6px 0 2px; }
.foot { padding:18px 24px 30px; text-align:center; }
.note {
  border:1px solid var(--line); border-left:3px solid var(--brand);
  background:var(--surface); border-radius:10px; padding:10px 14px; margin:10px 0;
}
@media print {
  body { background:#fff; }
  .topbar { position:static; }
  .btn, .filter { display:none; }
  .card, table { box-shadow:none; }
}
"""


# --- Embedded JavaScript -------------------------------------------------

_JS = """
(function () {
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem('safeai-theme'); } catch (e) {}
  if (saved === 'dark') { root.setAttribute('data-theme', 'dark'); }
  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var dark = root.getAttribute('data-theme') === 'dark';
      root.setAttribute('data-theme', dark ? 'light' : 'dark');
      try { localStorage.setItem('safeai-theme', dark ? 'light' : 'dark'); } catch (e) {}
    });
  }
  var inputs = document.querySelectorAll('input[data-filter]');
  inputs.forEach(function (input) {
    input.addEventListener('input', function () {
      var table = document.getElementById(input.getAttribute('data-filter'));
      if (!table) return;
      var q = input.value.toLowerCase();
      var rows = table.querySelectorAll('tbody tr');
      rows.forEach(function (row) {
        row.style.display = row.textContent.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
      });
    });
  });
})();
"""
