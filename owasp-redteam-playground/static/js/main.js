/* Top-level orchestration: nav switching + settings page. */

document.addEventListener('DOMContentLoaded', async () => {

  // ── Top nav: switch between views ──────────────────────
  document.querySelectorAll('.nav-btn').forEach(b => {
    b.addEventListener('click', () => {
      const view = b.dataset.view;
      document.querySelectorAll('.nav-btn').forEach(x => x.classList.toggle('active', x === b));
      document.querySelectorAll('.view').forEach(v => v.hidden = v.dataset.view !== view);
      if (view === 'docs' && !Docs._initialized) {
        Docs.init();
        Docs._initialized = true;
      }
      if (view === 'settings') {
        Settings.refresh();
      }
    });
  });

  // ── Wizard + Settings init ─────────────────────────────
  await Wizard.init();
  await Settings.init();
});

/* ─── Settings page wiring ─── */

const Settings = {
  config: null,
  models: [],

  async init() {
    const [cfg, models] = await Promise.all([API.getConfig(), API.getModels()]);
    this.config = cfg;
    this.models = models.models;

    document.getElementById('configPath').textContent = cfg.config_path || '~/.owasp-redteam/config.json';

    const modelSel = document.getElementById('defaultModel');
    modelSel.innerHTML = this.models.map(m =>
      `<option value="${m.id}" ${m.id === cfg.default_model ? 'selected' : ''}>${m.label}</option>`
    ).join('');

    document.getElementById('defaultSystemPrompt').value = cfg.default_system_prompt;
    document.getElementById('defaultTemperature').value = cfg.default_temperature;
    document.getElementById('defaultTemperatureVal').textContent = Number(cfg.default_temperature).toFixed(1);
    document.getElementById('defaultTemperature').addEventListener('input', e => {
      document.getElementById('defaultTemperatureVal').textContent = Number(e.target.value).toFixed(1);
    });

    this.renderStatus();
    document.getElementById('saveSettings').addEventListener('click', () => this.save());
  },

  async refresh() {
    this.config = await API.getConfig();
    this.renderStatus();
  },

  renderStatus() {
    const el = document.getElementById('configStatus');
    if (this.config.configured) {
      el.textContent = 'API key configured \u2713';
      el.className = 'config-status ok';
      document.getElementById('apiKeyInput').placeholder = 'sk-... (saved \u2014 leave blank to keep)';
    } else {
      el.textContent = 'No API key set yet.';
      el.className = 'config-status missing';
    }
  },

  async save() {
    const updates = {
      default_model: document.getElementById('defaultModel').value,
      default_system_prompt: document.getElementById('defaultSystemPrompt').value,
      default_temperature: parseFloat(document.getElementById('defaultTemperature').value),
    };
    const newKey = document.getElementById('apiKeyInput').value.trim();
    if (newKey) updates.api_key = newKey;

    await API.saveConfig(updates);
    document.getElementById('apiKeyInput').value = '';
    this.config = await API.getConfig();
    this.renderStatus();

    const msg = document.getElementById('saveMsg');
    msg.textContent = 'Saved';
    msg.classList.add('shown');
    setTimeout(() => msg.classList.remove('shown'), 1800);
  },
};
