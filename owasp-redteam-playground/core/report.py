"""Render a self-contained HTML security report.

The same template is used by the inline-in-app report and the downloadable
standalone file. JSON data is injected at render time. No external CDNs needed
\u2014 the file works offline by double-click.
"""

from __future__ import annotations

import json
from typing import Any


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AI Security Report</title>
<style>
  :root {
    --bg: #f6f7fb; --surface: #fff; --surface-soft: #f9fafc;
    --border: #e5e8ef; --text: #1a1f2e; --text-soft: #4a5468; --muted: #7a8499;
    --brand: #5b6cff; --brand-soft: #eef0ff;
    --good: #10b981; --good-soft: #d1fae5;
    --bad: #ef4444; --bad-soft: #fee2e2;
    --crit: #dc2626; --crit-soft: #fee2e2;
    --high: #ea580c; --high-soft: #ffedd5;
    --med:  #d97706; --med-soft:  #fef3c7;
    --shadow-sm: 0 1px 2px rgba(15,23,42,.05);
    --shadow: 0 4px 12px rgba(15,23,42,.06);
    --shadow-lg: 0 12px 32px rgba(15,23,42,.08);
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .wrap { max-width: 1080px; margin: 0 auto; padding: 32px 22px 80px; }
  .header { text-align: center; padding: 16px 0 8px; }
  .header .eyebrow { display: inline-block; background: var(--brand-soft); color: var(--brand);
    padding: 5px 14px; border-radius: 999px; font-size: 12px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; }
  .header h1 { font-size: 30px; margin: 14px 0 8px; letter-spacing: -.02em; }
  .header .sub { color: var(--text-soft); font-size: 15px; margin: 0; }
  .header .meta { color: var(--muted); font-size: 13px; margin-top: 12px; }
  .header .meta strong { color: var(--text-soft); font-weight: 600; }

  .scorecard { background: var(--surface); border-radius: 18px; padding: 28px;
    box-shadow: var(--shadow-lg); margin: 28px 0;
    display: grid; grid-template-columns: auto 1fr; gap: 32px; align-items: center; }
  .ring-wrap { position: relative; width: 160px; height: 160px; }
  .ring-wrap svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .ring-bg { fill: none; stroke: var(--border); stroke-width: 14; }
  .ring-fg { fill: none; stroke-width: 14; stroke-linecap: round; transition: stroke-dashoffset 1s ease-out; }
  .ring-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .ring-center .pct { font-size: 36px; font-weight: 700; line-height: 1; }
  .ring-center .label { font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .08em; }
  .scorecard-content h2 { margin: 0 0 6px; font-size: 22px; }
  .scorecard-content .verdict { font-size: 15px; color: var(--text-soft); margin: 0 0 18px; }
  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
  .stat { background: var(--surface-soft); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; }
  .stat .num { font-size: 22px; font-weight: 700; line-height: 1; }
  .stat .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; margin-top: 4px; }
  .stat.good .num { color: var(--good); }
  .stat.bad .num { color: var(--bad); }

  .section { margin: 32px 0; }
  .section > h2 { font-size: 20px; margin: 0 0 6px; display: flex; align-items: center; gap: 10px; }
  .section > h2 .badge { font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 999px;
    background: var(--bad-soft); color: var(--bad); letter-spacing: .04em; }
  .section > .lede { color: var(--text-soft); margin: 0 0 16px; }

  .finding { background: var(--surface); border: 1px solid var(--border); border-left: 5px solid var(--bad);
    border-radius: 14px; padding: 22px 24px; margin-bottom: 16px; box-shadow: var(--shadow); }
  .finding .head { display: flex; justify-content: space-between; gap: 16px; margin-bottom: 4px; }
  .finding .head h3 { margin: 0; font-size: 16px; flex: 1; }
  .finding .head .pill { background: var(--bad-soft); color: var(--bad); padding: 3px 10px; border-radius: 999px;
    font-size: 11px; font-weight: 700; letter-spacing: .04em; white-space: nowrap; }
  .finding .id { font-family: ui-monospace, monospace; color: var(--muted); font-size: 12px; margin-bottom: 12px; }
  .finding .row { margin-top: 14px; }
  .finding .row h4 { margin: 0 0 6px; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; font-weight: 600; }
  .finding .qt { background: var(--surface-soft); border: 1px solid var(--border); border-radius: 10px;
    padding: 12px 14px; font-family: ui-monospace, monospace; font-size: 13px; color: var(--text-soft);
    white-space: pre-wrap; word-break: break-word; }
  .finding .qt.harm { border-color: #fda4af; background: #fff5f6; color: #881337; }
  .finding .fix { background: var(--brand-soft); border-radius: 10px; padding: 12px 14px; color: #2937c7; font-size: 14px; }

  .cats { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }
  .cat { background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
    padding: 18px 20px; box-shadow: var(--shadow-sm); }
  .cat .head { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 10px; }
  .cat .name { font-weight: 600; font-size: 15px; flex: 1; }
  .cat .status { font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 999px; letter-spacing: .04em; white-space: nowrap; }
  .cat .status.pass { background: var(--good-soft); color: var(--good); }
  .cat .status.fail { background: var(--bad-soft); color: var(--bad); }
  .cat .desc { color: var(--text-soft); font-size: 13px; margin: 0 0 12px; }
  .cat .bar { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; margin-bottom: 8px; }
  .cat .bar.has-fail > div { background: linear-gradient(to right, var(--good) 0%, var(--good) var(--pct),
    var(--bad) var(--pct), var(--bad) 100%); height: 100%; }
  .cat .bar.all-pass > div { background: var(--good); height: 100%; }
  .cat .tests { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border); }
  .cat .test-row { display: flex; gap: 8px; padding: 6px 0; align-items: center; font-size: 13px; }
  .cat .test-row .ic.pass { color: var(--good); }
  .cat .test-row .ic.fail { color: var(--bad); }
  .cat .test-row .nm { flex: 1; color: var(--text-soft); }

  footer { text-align: center; color: var(--muted); font-size: 13px; margin-top: 36px; }
  @media (max-width: 720px) {
    .scorecard { grid-template-columns: 1fr; text-align: center; }
    .ring-wrap { margin: 0 auto; }
    .stats { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header class="header">
    <span class="eyebrow">AI Security Audit</span>
    <h1>How safe is your agent?</h1>
    <p class="sub">Plain-English report card from your red team run.</p>
    <div class="meta">
      <strong>Target:</strong> <span id="target">\u2014</span> &middot;
      <strong>Tested:</strong> <span id="when">\u2014</span>
    </div>
  </header>

  <section class="scorecard">
    <div class="ring-wrap">
      <svg viewBox="0 0 200 200">
        <circle cx="100" cy="100" r="80" class="ring-bg" />
        <circle cx="100" cy="100" r="80" class="ring-fg" id="ring" />
      </svg>
      <div class="ring-center"><div class="pct" id="pct">\u2014</div><div class="label">Pass rate</div></div>
    </div>
    <div class="scorecard-content">
      <h2 id="headline">Overall result</h2>
      <p class="verdict" id="verdict">\u2014</p>
      <div class="stats">
        <div class="stat good"><div class="num" id="passNum">0</div><div class="lbl">Passed</div></div>
        <div class="stat bad"><div class="num" id="failNum">0</div><div class="lbl">Failed</div></div>
        <div class="stat"><div class="num" id="totalNum">0</div><div class="lbl">Total</div></div>
      </div>
    </div>
  </section>

  <section class="section" id="findingsSection">
    <h2>Issues found <span class="badge" id="findingsBadge">0</span></h2>
    <p class="lede">Tests where the AI did not refuse. Each shows what was tried, the actual response, and how to fix it.</p>
    <div id="findings"></div>
  </section>

  <section class="section">
    <h2>Results by category</h2>
    <p class="lede">All tests grouped into the OWASP Agentic AI Top 10 categories.</p>
    <div class="cats" id="cats"></div>
  </section>

  <footer>Generated by the OWASP Agentic AI red team webapp.</footer>
</div>

<script id="report-data" type="application/json">__JSON__</script>
<script>
(function() {
  const DATA = JSON.parse(document.getElementById('report-data').textContent);
  const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  const trunc = (s, n) => { s = String(s||''); return s.length > n ? s.slice(0,n) + '\u2026' : s; };

  document.getElementById('target').textContent = DATA.target || '\u2014';
  document.getElementById('when').textContent = DATA.timestamp
    ? new Date(DATA.timestamp).toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short' })
    : '\u2014';

  const total = DATA.summary.total_tests;
  const fail  = DATA.summary.vulnerable;
  const pass  = DATA.summary.not_vulnerable;
  const pct   = total ? Math.round((pass/total)*100) : 0;

  document.getElementById('pct').textContent = pct + '%';
  document.getElementById('passNum').textContent = pass;
  document.getElementById('failNum').textContent = fail;
  document.getElementById('totalNum').textContent = total;

  const ring = document.getElementById('ring');
  const C = 2 * Math.PI * 80;
  ring.setAttribute('stroke-dasharray', C);
  ring.setAttribute('stroke-dashoffset', C);
  const ringColor = fail === 0 ? 'var(--good)' : fail <= 3 ? '#f59e0b' : 'var(--bad)';
  ring.setAttribute('stroke', ringColor.startsWith('var') ? getComputedStyle(document.documentElement).getPropertyValue(ringColor.slice(4,-1)).trim() : ringColor);
  setTimeout(() => ring.setAttribute('stroke-dashoffset', C * (1 - pct/100)), 80);

  let headline, verdict;
  if (fail === 0) {
    headline = 'Looking good';
    verdict = `The AI <strong>passed all ${total} test${total===1?'':'s'}</strong>. Resisted every attack we tried. Re-run periodically to catch regressions.`;
  } else if (fail <= 3) {
    headline = 'A few weak spots';
    verdict = `Passed <strong>${pass} of ${total}</strong> but failed <strong>${fail}</strong>. Address the issues below.`;
  } else {
    headline = 'Significant weaknesses';
    verdict = `Failed <strong>${fail} of ${total} tests</strong>. Needs work before this agent ships to users.`;
  }
  document.getElementById('headline').textContent = headline;
  document.getElementById('verdict').innerHTML = verdict;

  const failed = DATA.results.filter(r => r.vulnerable);
  const findingsEl = document.getElementById('findings');
  const badge = document.getElementById('findingsBadge');
  if (failed.length === 0) {
    badge.textContent = '0';
    badge.style.background = 'var(--good-soft)';
    badge.style.color = 'var(--good)';
    findingsEl.innerHTML = `<div class="finding" style="border-left-color: var(--good);">
      <div class="head"><h3>Nothing failed in this run</h3>
        <span class="pill" style="background: var(--good-soft); color: var(--good);">ALL CLEAR</span></div>
      <p style="margin: 10px 0 0; color: var(--text-soft);">Every attack was refused. Keep in mind: this run used these specific payloads. A clever attacker may still find phrasings that evade detection.</p>
    </div>`;
  } else {
    badge.textContent = failed.length;
    findingsEl.innerHTML = failed.map(r => `
      <div class="finding">
        <div class="head">
          <h3>${esc(r.category_friendly || r.category)} \u2014 ${esc(r.scenario)}</h3>
          <span class="pill">${esc(r.severity)}</span>
        </div>
        <div class="id">${esc(r.attack_id)}</div>
        <div class="row"><h4>What we asked</h4><div class="qt">${esc(trunc(r.payload, 600))}</div></div>
        <div class="row"><h4>What the AI replied</h4><div class="qt harm">${esc(trunc(r.response, 600))}</div></div>
        <div class="row"><h4>How to fix it</h4><div class="fix">${esc(r.recommendation)}</div></div>
      </div>
    `).join('');
  }

  const cats = {};
  DATA.results.forEach(r => {
    const k = r.attack_id.split('-')[0];
    if (!cats[k]) cats[k] = { id: k, name: r.category_friendly || r.category, desc: '', results: [] };
    cats[k].results.push(r);
  });

  const catsEl = document.getElementById('cats');
  catsEl.innerHTML = Object.values(cats).map(c => {
    const failCount = c.results.filter(r => r.vulnerable).length;
    const passCount = c.results.length - failCount;
    const passPct = (passCount / c.results.length) * 100;
    const status = failCount === 0
      ? `<span class="status pass">${passCount}/${c.results.length} passed</span>`
      : `<span class="status fail">${failCount} failed</span>`;
    return `<div class="cat">
      <div class="head"><div class="name">${esc(c.name)}</div>${status}</div>
      <div class="bar ${failCount > 0 ? 'has-fail' : 'all-pass'}" style="--pct: ${passPct}%;"><div style="width: ${passPct}%;"></div></div>
      <div class="tests">${c.results.map(r => `
        <div class="test-row">
          <span class="ic ${r.vulnerable ? 'fail' : 'pass'}">${r.vulnerable ? '\u2715' : '\u2713'}</span>
          <span class="nm">${esc(r.scenario)}</span>
        </div>
      `).join('')}</div>
    </div>`;
  }).join('');
})();
</script>
</body>
</html>
"""


def render(report: dict[str, Any]) -> str:
    """Render the report dict as a self-contained HTML string."""
    json_blob = json.dumps(report).replace("</", r"<\/")
    return _TEMPLATE.replace("__JSON__", json_blob)
