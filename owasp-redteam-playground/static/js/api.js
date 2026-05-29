/* API client — thin fetch wrappers for the backend. */

const API = {
  async getConfig() {
    const r = await fetch('/api/config');
    return r.json();
  },
  async saveConfig(updates) {
    const r = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    return r.json();
  },
  async getModels() {
    const r = await fetch('/api/models');
    return r.json();
  },
  async getScenarios() {
    const r = await fetch('/api/scenarios');
    return r.json();
  },
  async getAgentTemplate() {
    const r = await fetch('/api/agent-template');
    return r.json();
  },
  async startRun(spec) {
    const r = await fetch('/api/runs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(spec),
    });
    return r.json();
  },
  async cancelRun(id) {
    const r = await fetch(`/api/runs/${id}/cancel`, { method: 'POST' });
    return r.json();
  },
  async getRunResults(id) {
    const r = await fetch(`/api/runs/${id}/results`);
    return r.json();
  },
  reportUrl(id) {
    return `/api/runs/${id}/report.html`;
  },
  streamEvents(id, onEvent) {
    const es = new EventSource(`/api/runs/${id}/events`);
    ['started', 'progress', 'result', 'finished', 'error'].forEach(name => {
      es.addEventListener(name, e => {
        try {
          onEvent(name, JSON.parse(e.data));
        } catch (err) {
          console.error('event parse', err, e.data);
        }
      });
    });
    es.onerror = () => {
      // EventSource auto-reconnects; close once finished message was received.
    };
    return es;
  },
  async getDocsList() {
    const r = await fetch('/api/docs');
    return r.json();
  },
  async getDocContent(id) {
    const r = await fetch(`/api/docs/${id}`);
    return r.text();
  },
};
