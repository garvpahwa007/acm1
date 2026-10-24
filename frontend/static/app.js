const $ = (selector) => document.querySelector(selector);
    const urlTab = $('#urlTab');
    const emailTab = $('#emailTab');
    const urlForm = $('#urlForm');
    const emailForm = $('#emailForm');
    const urlInput = $('#urlInput');
    const emailInput = $('#emailInput');
    const toast = $('#toast');
    let currentMode = 'url';
    let history;
    try { history = JSON.parse(localStorage.getItem('phishguard-history') || '[]'); }
    catch { history = []; }
    if (!Array.isArray(history)) history = [];
    const API_BASE = '';
    let scanBusy = false;

    const icons = {
      good: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m5 12 4 4L19 6"/></svg>',
      warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 9v4M12 17h.01"/></svg>',
      bad: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></svg>',
      link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1L11 5"/><path d="M14 11a5 5 0 0 0-7.1-.1l-2 2A5 5 0 0 0 7 20l1-1"/></svg>'
    };

    function showToast(message) {
      toast.textContent = message;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2800);
    }

    function setMode(mode) {
      currentMode = mode;
      const isUrl = mode === 'url';
      urlTab.classList.toggle('active', isUrl);
      emailTab.classList.toggle('active', !isUrl);
      urlTab.setAttribute('aria-selected', String(isUrl));
      emailTab.setAttribute('aria-selected', String(!isUrl));
      urlForm.style.display = isUrl ? 'grid' : 'none';
      emailForm.style.display = isUrl ? 'none' : 'block';
    }
    urlTab.addEventListener('click', () => setMode('url'));
    emailTab.addEventListener('click', () => setMode('email'));

    async function backendScan(path, payload) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 60000);
      try {
        const response = await fetch(`${API_BASE}${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'The scan could not be completed.');
        return data;
      } finally { clearTimeout(timer); }
    }

    function toDashboardResult(data, target) {
      const labels = { malicious: 'Malicious', suspicious: 'Suspicious', likely_safe: 'Likely safe', unknown: 'Unknown' };
      const color = data.label === 'malicious' ? '#d74955' :
        ['suspicious', 'unknown'].includes(data.label) || data.tier === 'low' ? '#d58b12' : '#17a673';
      const findings = (data.signals || []).map(signal => ({
        type: ['critical', 'high'].includes(signal.severity) ? 'bad' : signal.severity === 'info' ? 'good' : 'warn',
        title: signal.title,
        body: [signal.evidence, signal.tip].filter(Boolean).join(' ')
      }));
      if (!findings.length) findings.push({ type: 'good', title: 'No indicators fired', body: data.explain || 'Absence of indicators is not a guarantee of safety.' });
      for (const note of data.intel_notes || []) findings.push({ type: 'warn', title: 'Verification coverage', body: note });
      if (data.receipt_id) findings.push({ type: 'good', title: 'Verdict receipt', body: data.receipt_id });
      return {
        score: data.score,
        label: labels[data.label] || data.label,
        summary: data.headline,
        target: data.email?.subject || data.facts?.url || target,
        color, findings,
        meta: `${data.speed === 'quick' ? 'Initial lexical check' : 'Engine analysis'} · ${data.confidence_text || data.confidence}`
      };
    }

    async function scan(mode, payload) {
      if (scanBusy) { showToast('A scan is already running.'); return; }
      scanBusy = true;
      const panel = mode === 'url' ? urlForm : emailForm;
      const submit = panel.querySelector('[type="submit"]');
      submit.disabled = true;
      panel.classList.add('loading');
      try {
        let data;
        if (mode === 'url') {
          data = await backendScan('/api/check/url?mode=quick', payload);
          renderResult(toDashboardResult(data, payload.url));
          $('#resultsCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          try { data = await backendScan('/api/check/url?mode=full', payload); }
          catch (error) {
            data.intel_notes = [...(data.intel_notes || []), 'Full verification did not finish. This result uses lexical checks only.'];
            showToast('Full verification unavailable; showing the initial lexical result.');
          }
        } else {
          data = await backendScan('/api/check/email', payload);
        }
        const result = toDashboardResult(data, mode === 'url' ? payload.url : 'Email message');
        renderResult(result);
        addHistory(result, mode);
        $('#resultsCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      } catch (error) {
        showToast(error.name === 'AbortError' ? 'The engine timed out. Please try again.' : error.message || 'Cannot reach the engine. Start the Flask server and try again.');
      } finally {
        scanBusy = false;
        submit.disabled = false;
        panel.classList.remove('loading');
      }
    }

    function renderResult(result) {
      $('#emptyState').style.display = 'none';
      $('#resultContent').style.display = 'block';
      $('#scoreValue').textContent = result.score;
      $('#riskLabel').textContent = result.label;
      $('#riskSummary').textContent = result.summary;
      $('#scannedTarget').textContent = result.target;
      $('#scanTime').textContent = result.meta;
      const color = result.color;
      const start = 0;
      $('#gauge').style.background = `conic-gradient(${color} 0 ${Math.max(start, result.score)}%, #e8edf2 ${Math.max(start, result.score)}% 100%)`;
      $('#riskLabel').style.color = color;
      $('#findingList').innerHTML = result.findings.map(f => `<div class="finding ${f.type}">${icons[f.type]}<div><strong>${escapeHtml(f.title)}</strong><span>${escapeHtml(f.body)}</span></div></div>`).join('');
    }

    function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#039;', '"':'&quot;' }[char])); }

    function addHistory(result, mode) {
      history.unshift({ target: result.target, score: result.score, label: result.label, mode, time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) });
      history = history.slice(0, 5);
      localStorage.setItem('phishguard-history', JSON.stringify(history));
      renderHistory();
    }

    function renderHistory() {
      if (!history.length) { $('#recentList').innerHTML = '<div class="empty-state" style="min-height: 100px"><span>No recent scans yet.</span></div>'; return; }
      $('#recentList').innerHTML = history.map(item => {
        const pill = item.label === 'Malicious' || item.label === 'High risk' ? 'danger' : ['Suspicious', 'Unknown'].includes(item.label) ? 'suspicious' : 'safe';
        return `<div class="recent-item"><div class="recent-main"><div class="recent-icon">${item.mode === 'url' ? icons.link : '✉'}</div><div><strong title="${escapeHtml(item.target)}">${escapeHtml(item.target)}</strong><span>${item.mode === 'url' ? 'URL scan' : 'Email analysis'} · ${escapeHtml(item.time)}</span></div></div><span class="pill ${pill}">${escapeHtml(item.label)} · ${escapeHtml(item.score)}</span></div>`;
      }).join('');
    }

    urlForm.addEventListener('submit', event => {
      event.preventDefault();
      const url = urlInput.value.trim();
      if (!url) { showToast('Paste a URL to start the scan.'); urlInput.focus(); return; }
      scan('url', { url });
    });
    emailForm.addEventListener('submit', event => {
      event.preventDefault();
      const raw = emailInput.value.trim();
      if (!raw) { showToast('Paste an email or upload a file first.'); emailInput.focus(); return; }
      scan('email', { raw });
    });
    $('#sampleBtn').addEventListener('click', async () => {
      if (scanBusy) { showToast('A scan is already running.'); return; }
      if (currentMode === 'url') {
        urlInput.value = 'http://paypal-security-verification.xyz/login?verify=urgent';
        scan('url', { url: urlInput.value });
      } else {
        try {
          const response = await fetch('/api/sample/bec_invoice');
          if (!response.ok) throw new Error('Could not load the sample email.');
          emailInput.value = await response.text();
          scan('email', { raw: emailInput.value });
        } catch (error) { showToast(error.message); }
      }
    });
    $('#uploadBtn').addEventListener('click', () => $('#fileInput').click());
    $('#fileInput').addEventListener('change', event => { const file = event.target.files[0]; if (!file) return; $('#fileName').textContent = file.name; const reader = new FileReader(); reader.onload = () => { emailInput.value = reader.result; showToast('Email file loaded locally. Ready to analyze.'); }; reader.readAsText(file); });
    $('#clearHistory').addEventListener('click', () => { history = []; localStorage.removeItem('phishguard-history'); renderHistory(); showToast('Scan history cleared.'); });
    document.querySelectorAll('.nav button').forEach(button => button.addEventListener('click', () => { document.querySelectorAll('.nav button').forEach(item => item.classList.remove('active')); button.classList.add('active'); if (button.textContent.includes('URL Scanner')) setMode('url'); if (button.textContent.includes('Email Analyzer')) setMode('email'); document.getElementById(button.dataset.scroll).scrollIntoView({ behavior: 'smooth' }); }));
    renderHistory();

    fetch('/api/health').then(response => {
      if (!response.ok) throw new Error('Engine unavailable');
      return response.json();
    }).then(data => {
      $('.live-status').lastChild.textContent = ' Engine connected';
      $('#intelStatus').textContent = data.intel.safe_browsing || data.intel.virustotal ? 'Keys configured' : 'Optional keys';
    }).catch(() => {
      $('.live-status').lastChild.textContent = ' Engine unavailable';
      $('#intelStatus').textContent = 'Unavailable';
    });
