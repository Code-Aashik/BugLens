let allBugs = [];
let activeFilter = 'All';

function updateLineNumbers() {
  const lines = document.getElementById('codeInput').value.split('\n').length;
  const ln    = document.getElementById('lineNums');
  ln.innerHTML = Array.from({length: lines}, (_, i) => `<span>${i + 1}</span>`).join('');
}

function syncScroll() {
  const ta = document.getElementById('codeInput');
  document.getElementById('lineNums').scrollTop = ta.scrollTop;
}

function onCodeChange() {
  const val = document.getElementById('codeInput').value;
  document.getElementById('charCount').textContent = val.length;
  const lines = val.split('\n').length;
  document.getElementById('lineCount').textContent = lines + ' line' + (lines !== 1 ? 's' : '');
  updateLineNumbers();
}

function clearAll() {
  document.getElementById('codeInput').value = '';
  onCodeChange();
  document.getElementById('placeholder').style.display = 'flex';
  document.getElementById('resultsContent').style.display = 'none';
  document.getElementById('spinnerWrap').style.display = 'none';
  document.getElementById('resultsTitle').textContent = 'Bug Report';
  document.getElementById('resultsSubtitle').textContent = '— paste code and analyse';
  allBugs = [];
}

function setFilter(f) {
  activeFilter = f;
  document.querySelectorAll('.fpill').forEach(p => {
    p.className = 'fpill';
    if (p.dataset.f === f) p.classList.add('f-' + f.toLowerCase().replace(' ',''));
  });
  renderBugList();
}

function renderBugList() {
  const filtered = activeFilter === 'All' ? allBugs : allBugs.filter(b => b.severity === activeFilter);
  const el = document.getElementById('bugList');
  if (!el) return;

  if (filtered.length === 0) {
    el.innerHTML = `<p style="color:var(--muted);font-size:0.82rem;padding:12px 0">No ${activeFilter === 'All' ? '' : activeFilter + ' severity '}bugs to display.</p>`;
    return;
  }

  el.innerHTML = filtered.map((bug, i) => `
    <div class="bug-card ${bug.severity}" style="animation-delay:${i * 0.05}s">
      <div class="bc-header">
        <span class="sev-badge ${bug.severity}">${bug.severity}</span>
        <span class="type-badge">${bug.type || 'Bug'}</span>
        ${bug.cwe_id ? `<span class="cwe-badge">${bug.cwe_id}</span>` : ''}
        <span class="conf-badge" title="${bug.confirmed_runs} of ${bug.total_runs} runs agreed">
          ✓ ${Math.round(bug.confidence * 100)}% confidence
        </span>
        <span class="bug-num">#${bug.bug_id}</span>
      </div>
      <div class="bc-loc">📍 <code>${bug.location}</code></div>
      <div class="bc-desc">${bug.description}</div>
      <div class="fix-head">💡 Suggested Fix</div>
      <div class="fix-body">${bug.fix}</div>
    </div>`).join('');
}

async function runAnalysis() {
  const language = document.getElementById('language').value;
  const code     = document.getElementById('codeInput').value.trim();
  const btn      = document.getElementById('analyseBtn');

  if (!code) { alert('Please paste some code first.'); return; }

  btn.disabled = true;
  btn.textContent = 'Analysing...';
  document.getElementById('placeholder').style.display = 'none';
  document.getElementById('resultsContent').style.display = 'none';
  document.getElementById('spinnerWrap').style.display = 'flex';
  document.getElementById('resultsTitle').textContent = 'Analysing...';
  document.getElementById('resultsSubtitle').textContent = 'Running 5 LLM passes + voting...';

  try {
    const res  = await fetch('/analyse', {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ code, language })
    });
    const data = await res.json();

    document.getElementById('spinnerWrap').style.display = 'none';
    document.getElementById('resultsContent').style.display = 'block';

    if (data.error) {
      document.getElementById('resultsTitle').textContent = 'Error';
      document.getElementById('resultsSubtitle').textContent = '';
      document.getElementById('resultsContent').innerHTML = `<div class="err-box">⚠️ ${data.error}</div>`;
      return;
    }

    allBugs      = data.bugs || [];
    activeFilter = 'All';
    const s      = data.summary || {};

    document.getElementById('resultsTitle').textContent = 'Bug Report';
    document.getElementById('resultsSubtitle').textContent =
      `— ${data.language} · ${data.elapsed_sec}s · ${s.total} confirmed bug${s.total !== 1 ? 's' : ''}`;

    if (allBugs.length === 0) {
      document.getElementById('resultsContent').innerHTML = `
        <div class="no-bugs">
          <div class="nb-icon">✅</div>
          <h3>No bugs detected</h3>
          <p>No issues were confirmed across ${data.n_runs} analysis runs.</p>
        </div>`;
      return;
    }

    const riskColors = {
      'Clean': '#4ff7a0', 'Low Risk': '#8a9ff8',
      'Medium Risk': '#f7b84f', 'High Risk': '#f7614f'
    };
    const rc = riskColors[s.risk_level] || '#8a9ff8';

    const cweTags = (data.retrieved_cwes || []).map(c =>
      `<span class="cwe-tag">${c}</span>`).join('');

    document.getElementById('resultsContent').innerHTML = `
      <div class="summary-grid">
        <div class="s-card">
          <div class="s-icon">🐛</div>
          <div class="s-num" style="color:var(--accent)">${s.total}</div>
          <div class="s-lbl">Total Bugs</div>
        </div>
        <div class="s-card">
          <div class="s-icon">🔴</div>
          <div class="s-num" style="color:var(--high)">${s.high}</div>
          <div class="s-lbl">High Severity</div>
        </div>
        <div class="s-card">
          <div class="s-icon">🟡</div>
          <div class="s-num" style="color:var(--medium)">${s.medium}</div>
          <div class="s-lbl">Medium Severity</div>
        </div>
        <div class="s-card">
          <div class="s-icon">🟢</div>
          <div class="s-num" style="color:var(--low)">${s.low}</div>
          <div class="s-lbl">Low Severity</div>
        </div>
        <div class="s-card">
          <div class="s-icon">⚠️</div>
          <div class="s-num" style="color:${rc};font-size:1.4rem">${s.risk_score}</div>
          <div class="s-lbl">Risk Score</div>
          <div class="s-risk-lbl" style="background:${rc}18;color:${rc};border:1px solid ${rc}40">${s.risk_level}</div>
        </div>
      </div>

      <div class="meta-strip">
        <span>🤖 <b>${data.model}</b></span>
        <span>💻 <b>${data.language}</b></span>
        <span>⏱ <b>${data.elapsed_sec}s</b></span>
        <span>🔁 <b>${data.n_runs} runs</b> · kept ≥${data.k_threshold}</span>
        <span>📊 Score = (H×3)+(M×2)+(L×1) = <b>${s.risk_score}</b></span>
      </div>

      ${cweTags ? `<div class="cwe-strip"><span style="font-size:0.7rem;color:var(--muted);margin-right:8px">🔍 CWEs retrieved:</span>${cweTags}</div>` : ''}

      <div class="filter-row">
        <button class="fpill f-all"    data-f="All"    onclick="setFilter('All')">All ${s.total}</button>
        <button class="fpill"          data-f="High"   onclick="setFilter('High')">🔴 High ${s.high}</button>
        <button class="fpill"          data-f="Medium" onclick="setFilter('Medium')">🟡 Medium ${s.medium}</button>
        <button class="fpill"          data-f="Low"    onclick="setFilter('Low')">🟢 Low ${s.low}</button>
      </div>

      <div id="bugList"></div>`;

    renderBugList();

  } catch (err) {
    document.getElementById('spinnerWrap').style.display = 'none';
    document.getElementById('resultsContent').style.display = 'block';
    document.getElementById('resultsTitle').textContent = 'Error';
    document.getElementById('resultsContent').innerHTML =
      `<div class="err-box">⚠️ Network error: ${err.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = '⚡ Analyse Code';
  }
}

updateLineNumbers();