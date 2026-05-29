/* Wizard state machine — the 5-step flow. */

const Wizard = {
  state: {
    step: 1,
    models: [],
    selectedModel: 'gpt-4o',
    customModel: '',
    scenarios: [],
    categories: [],
    selectedScenarios: new Set(),
    agentMode: 'settings',
    systemPrompt: 'You are a helpful assistant.',
    temperature: 0.7,
    code: '',
    codeTemplate: '',
    payloadOverrides: {},
    currentRunId: null,
    eventSource: null,
    codeEditor: null,
  },

  async init() {
    const [cfg, models, scenarios] = await Promise.all([
      API.getConfig(),
      API.getModels(),
      API.getScenarios(),
    ]);

    this.state.models = models.models;
    this.state.selectedModel = cfg.default_model;
    this.state.systemPrompt = cfg.default_system_prompt;
    this.state.temperature = cfg.default_temperature;
    this.state.scenarios = scenarios.scenarios;
    this.state.categories = scenarios.categories;
    this.state.selectedScenarios = new Set(scenarios.scenarios.map(s => s.id));

    this.bindStepNav();
    this.renderStep1();
    this.renderStep2();
    this.renderStep3();
    this.bindTabs();

    document.getElementById('selectAll').addEventListener('click', () => this.selectScenarios('all'));
    document.getElementById('selectNone').addEventListener('click', () => this.selectScenarios('none'));
    document.getElementById('selectCritical').addEventListener('click', () => this.selectScenarios('critical'));
    document.getElementById('resetCode').addEventListener('click', () => this.resetCode());
    document.getElementById('startRun').addEventListener('click', () => this.startRun());
    document.getElementById('cancelRun').addEventListener('click', () => this.cancelRun());
  },

  /* ─── Step nav ──────────────────────────────────────── */

  bindStepNav() {
    document.querySelectorAll('[data-next]').forEach(b => b.addEventListener('click', () => this.go(this.state.step + 1)));
    document.querySelectorAll('[data-prev]').forEach(b => b.addEventListener('click', () => this.go(this.state.step - 1)));
    document.querySelectorAll('.stepbar .step').forEach(el => {
      el.addEventListener('click', () => this.go(parseInt(el.dataset.step, 10)));
    });
  },

  go(step) {
    if (step < 1 || step > 5) return;
    if (step > this.state.step) {
      if (!this.canAdvanceFrom(this.state.step)) return;
    }
    this.state.step = step;
    document.querySelectorAll('.step-pane').forEach(p => {
      p.classList.toggle('active', parseInt(p.dataset.pane, 10) === step);
    });
    document.querySelectorAll('.stepbar .step').forEach(el => {
      const s = parseInt(el.dataset.step, 10);
      el.classList.toggle('active', s === step);
      el.classList.toggle('done', s < step);
    });

    if (step === 4) this.renderStep4();
    if (step === 5) this.renderStep5();
  },

  canAdvanceFrom(step) {
    if (step === 1) {
      const model = this.activeModelId();
      if (!model) {
        alert('Please pick a model.');
        return false;
      }
    }
    if (step === 2) {
      if (this.state.selectedScenarios.size === 0) {
        alert('Please select at least one test.');
        return false;
      }
    }
    if (step === 3 && this.state.agentMode === 'code') {
      const code = this.state.codeEditor ? this.state.codeEditor.getValue() : this.state.code;
      if (!code.trim()) {
        alert('Code mode requires non-empty agent source.');
        return false;
      }
      this.state.code = code;
    }
    return true;
  },

  /* ─── Step 1: model ─────────────────────────────────── */

  renderStep1() {
    const el = document.getElementById('modelList');
    el.innerHTML = this.state.models.map(m => `
      <div class="model-card ${m.id === this.state.selectedModel ? 'selected' : ''}" data-id="${m.id}">
        <div class="check"></div>
        <div class="body">
          <div class="name">${esc(m.label)}</div>
          <div class="desc">${esc(m.description)}</div>
        </div>
        <span class="tier ${m.tier}">${esc(m.tier)}</span>
      </div>
    `).join('');
    el.querySelectorAll('.model-card').forEach(c => {
      c.addEventListener('click', () => {
        this.state.selectedModel = c.dataset.id;
        this.state.customModel = '';
        document.getElementById('customModel').value = '';
        this.renderStep1();
      });
    });
    document.getElementById('customModel').addEventListener('input', e => {
      this.state.customModel = e.target.value.trim();
      if (this.state.customModel) {
        this.state.selectedModel = '';
        this.renderStep1();
      }
    });
  },

  activeModelId() {
    return this.state.customModel || this.state.selectedModel || '';
  },

  /* ─── Step 2: scenarios ─────────────────────────────── */

  renderStep2() {
    const el = document.getElementById('scenarioTree');
    const grouped = {};
    this.state.scenarios.forEach(s => {
      if (!grouped[s.category_id]) grouped[s.category_id] = [];
      grouped[s.category_id].push(s);
    });

    el.innerHTML = this.state.categories.map(c => {
      const items = grouped[c.id] || [];
      const allSel = items.every(s => this.state.selectedScenarios.has(s.id));
      const someSel = items.some(s => this.state.selectedScenarios.has(s.id));
      return `
        <div class="scenario-cat open" data-cat="${c.id}">
          <div class="scenario-cat-head">
            <input type="checkbox" class="cat-check" ${allSel ? 'checked' : ''} />
            <div class="cat-name">${esc(c.friendly)}</div>
            <div class="cat-meta">${items.filter(s => this.state.selectedScenarios.has(s.id)).length}/${items.length} \u00b7 ${c.id}</div>
            <span class="chev">\u25B8</span>
          </div>
          <div class="scenario-cat-body">
            ${items.map(s => `
              <label class="scenario-item">
                <input type="checkbox" data-scen-id="${s.id}" ${this.state.selectedScenarios.has(s.id) ? 'checked' : ''} />
                <div class="scen-body">
                  <div class="scen-name">${esc(s.scenario)}</div>
                  <div class="scen-id">${esc(s.id)}</div>
                </div>
                <span class="scen-sev ${esc(s.severity)}">${esc(s.severity)}</span>
              </label>
            `).join('')}
          </div>
        </div>
      `;
    }).join('');

    el.querySelectorAll('.scenario-cat-head').forEach(h => {
      h.addEventListener('click', e => {
        if (e.target.matches('input')) return;
        h.parentElement.classList.toggle('open');
      });
    });

    el.querySelectorAll('.cat-check').forEach(cb => {
      cb.addEventListener('click', e => {
        e.stopPropagation();
        const cat = cb.closest('.scenario-cat').dataset.cat;
        const items = grouped[cat] || [];
        if (cb.checked) {
          items.forEach(s => this.state.selectedScenarios.add(s.id));
        } else {
          items.forEach(s => this.state.selectedScenarios.delete(s.id));
        }
        this.renderStep2();
        this.updateSelCount();
      });
    });

    el.querySelectorAll('[data-scen-id]').forEach(cb => {
      cb.addEventListener('click', e => {
        e.stopPropagation();
        const id = cb.dataset.scenId;
        if (cb.checked) this.state.selectedScenarios.add(id);
        else this.state.selectedScenarios.delete(id);
        this.renderStep2();
        this.updateSelCount();
      });
    });

    this.updateSelCount();
  },

  selectScenarios(mode) {
    if (mode === 'all') {
      this.state.selectedScenarios = new Set(this.state.scenarios.map(s => s.id));
    } else if (mode === 'none') {
      this.state.selectedScenarios = new Set();
    } else if (mode === 'critical') {
      this.state.selectedScenarios = new Set(
        this.state.scenarios.filter(s => s.severity === 'CRITICAL').map(s => s.id)
      );
    }
    this.renderStep2();
  },

  updateSelCount() {
    document.getElementById('selCount').textContent = this.state.selectedScenarios.size;
  },

  /* ─── Step 3: agent ─────────────────────────────────── */

  renderStep3() {
    document.getElementById('systemPrompt').value = this.state.systemPrompt;
    document.getElementById('temperature').value = this.state.temperature;
    document.getElementById('temperatureVal').textContent = this.state.temperature.toFixed(1);

    document.getElementById('systemPrompt').addEventListener('input', e => {
      this.state.systemPrompt = e.target.value;
    });
    document.getElementById('temperature').addEventListener('input', e => {
      this.state.temperature = parseFloat(e.target.value);
      document.getElementById('temperatureVal').textContent = this.state.temperature.toFixed(1);
    });
  },

  bindTabs() {
    document.querySelectorAll('.tab').forEach(t => {
      t.addEventListener('click', () => {
        const target = t.dataset.tab;
        this.state.agentMode = target;
        document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.dataset.tab === target));
        if (target === 'code' && !this.state.codeEditor) {
          this.initCodeEditor();
        }
      });
    });
  },

  async initCodeEditor() {
    if (!this.state.codeTemplate) {
      const data = await API.getAgentTemplate();
      this.state.codeTemplate = data.source || '';
      this.state.code = this.state.codeTemplate;
    }
    const textarea = document.getElementById('agentCode');
    textarea.value = this.state.code;
    this.state.codeEditor = CodeMirror.fromTextArea(textarea, {
      mode: 'python',
      lineNumbers: true,
      theme: 'idea',
      indentUnit: 4,
      tabSize: 4,
    });
    this.state.codeEditor.on('change', () => {
      this.state.code = this.state.codeEditor.getValue();
    });
  },

  resetCode() {
    if (this.state.codeEditor && this.state.codeTemplate) {
      this.state.codeEditor.setValue(this.state.codeTemplate);
      this.state.code = this.state.codeTemplate;
    }
  },

  /* ─── Step 4: payload overrides ─────────────────────── */

  renderStep4() {
    const el = document.getElementById('payloadEditor');
    const selectedScenarios = this.state.scenarios.filter(s => this.state.selectedScenarios.has(s.id));
    if (selectedScenarios.length === 0) {
      el.innerHTML = '<p class="lede">No scenarios selected.</p>';
      return;
    }
    el.innerHTML = selectedScenarios.map(s => {
      const overridden = this.state.payloadOverrides[s.id] !== undefined;
      const value = overridden ? this.state.payloadOverrides[s.id] : s.default_payload;
      return `
        <div class="payload-card ${overridden ? 'modified' : ''}" data-id="${s.id}">
          <div class="pc-head">
            <span class="pc-id">${esc(s.id)}</span>
            <span class="pc-name">${esc(s.scenario)}</span>
            <span class="scen-sev ${esc(s.severity)}">${esc(s.severity)}</span>
          </div>
          <textarea data-payload-id="${s.id}">${esc(value)}</textarea>
          <button class="pc-reset" data-reset-id="${s.id}" ${overridden ? '' : 'hidden'}>Reset to default</button>
        </div>
      `;
    }).join('');

    el.querySelectorAll('[data-payload-id]').forEach(ta => {
      ta.addEventListener('input', e => {
        const id = ta.dataset.payloadId;
        const s = this.state.scenarios.find(x => x.id === id);
        if (e.target.value === s.default_payload) {
          delete this.state.payloadOverrides[id];
          ta.closest('.payload-card').classList.remove('modified');
          ta.closest('.payload-card').querySelector('[data-reset-id]').hidden = true;
        } else {
          this.state.payloadOverrides[id] = e.target.value;
          ta.closest('.payload-card').classList.add('modified');
          ta.closest('.payload-card').querySelector('[data-reset-id]').hidden = false;
        }
      });
    });

    el.querySelectorAll('[data-reset-id]').forEach(b => {
      b.addEventListener('click', () => {
        const id = b.dataset.resetId;
        const s = this.state.scenarios.find(x => x.id === id);
        delete this.state.payloadOverrides[id];
        const ta = b.parentElement.querySelector('textarea');
        ta.value = s.default_payload;
        b.parentElement.classList.remove('modified');
        b.hidden = true;
      });
    });
  },

  /* ─── Step 5: run ───────────────────────────────────── */

  renderStep5() {
    document.getElementById('runPanel').hidden = false;
    document.getElementById('progressPanel').hidden = true;
    document.getElementById('reportPanel').hidden = true;

    const count = this.state.selectedScenarios.size;
    document.getElementById('runCount').textContent = count;

    const overrideCount = Object.keys(this.state.payloadOverrides).length;
    const model = this.activeModelId();
    document.getElementById('runSummary').innerHTML = `
      <div class="row"><span class="lbl">Model:</span> <code>${esc(model)}</code></div>
      <div class="row"><span class="lbl">Agent mode:</span> ${esc(this.state.agentMode === 'code' ? 'Custom code' : 'Settings (system prompt + temperature)')}</div>
      <div class="row"><span class="lbl">Tests selected:</span> ${count}</div>
      <div class="row"><span class="lbl">Edited payloads:</span> ${overrideCount}</div>
    `;
  },

  async startRun() {
    const spec = {
      model: this.activeModelId(),
      agent_mode: this.state.agentMode,
      system_prompt: this.state.systemPrompt,
      temperature: this.state.temperature,
      code: this.state.code,
      scenario_ids: Array.from(this.state.selectedScenarios),
      payload_overrides: this.state.payloadOverrides,
    };

    const res = await API.startRun(spec);
    if (res.error) {
      alert(res.error);
      return;
    }
    this.state.currentRunId = res.run_id;

    document.getElementById('runPanel').hidden = true;
    document.getElementById('progressPanel').hidden = false;
    document.getElementById('reportPanel').hidden = true;
    document.getElementById('liveResults').innerHTML = '';
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('progressCount').textContent = '0';
    document.getElementById('progressTotal').textContent = spec.scenario_ids.length;

    this.state.eventSource = API.streamEvents(res.run_id, (name, data) => {
      this.onRunEvent(name, data);
    });
  },

  onRunEvent(name, data) {
    if (name === 'started') {
      document.getElementById('progressTotal').textContent = data.total;
    } else if (name === 'progress') {
      this.addLiveRow(data.attack_id, data.scenario, 'running', null);
      const pct = ((data.index) / data.total) * 100;
      document.getElementById('progressFill').style.width = pct + '%';
    } else if (name === 'result') {
      this.updateLiveRow(data.attack_id, data.scenario, data.vulnerable);
      document.getElementById('progressCount').textContent = data.index + 1;
      const pct = ((data.index + 1) / data.total) * 100;
      document.getElementById('progressFill').style.width = pct + '%';
    } else if (name === 'finished') {
      if (this.state.eventSource) {
        this.state.eventSource.close();
        this.state.eventSource = null;
      }
      this.renderReport(this.state.currentRunId);
    } else if (name === 'error') {
      alert('Run failed: ' + (data.message || 'unknown error'));
      if (this.state.eventSource) {
        this.state.eventSource.close();
        this.state.eventSource = null;
      }
    }
  },

  addLiveRow(id, name, status, vulnerable) {
    const el = document.getElementById('liveResults');
    let row = el.querySelector(`[data-id="${id}"]`);
    if (!row) {
      row = document.createElement('div');
      row.className = 'live-row running';
      row.dataset.id = id;
      row.innerHTML = `
        <span class="ic running">\u25CB</span>
        <span class="id">${esc(id)}</span>
        <span class="nm">${esc(name)}</span>
      `;
      el.appendChild(row);
      el.scrollTop = el.scrollHeight;
    }
  },

  updateLiveRow(id, name, vulnerable) {
    const el = document.getElementById('liveResults');
    const row = el.querySelector(`[data-id="${id}"]`);
    if (!row) return;
    row.classList.remove('running');
    row.classList.toggle('fail', vulnerable);
    row.querySelector('.ic').className = 'ic ' + (vulnerable ? 'fail' : 'pass');
    row.querySelector('.ic').textContent = vulnerable ? '\u2715' : '\u2713';
  },

  async cancelRun() {
    if (!this.state.currentRunId) return;
    await API.cancelRun(this.state.currentRunId);
  },

  renderReport(runId) {
    document.getElementById('progressPanel').hidden = true;
    const el = document.getElementById('reportPanel');
    el.hidden = false;
    el.innerHTML = `
      <div class="report-actions">
        <a class="btn primary" href="${API.reportUrl(runId)}" download>Download HTML report</a>
        <button class="btn" id="runAgain">Run again</button>
      </div>
      <iframe id="reportFrame" src="${API.reportUrl(runId)}"></iframe>
    `;
    document.getElementById('runAgain').addEventListener('click', () => this.go(1));
  },
};

function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
