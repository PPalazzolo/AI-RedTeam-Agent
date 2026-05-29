/* Docs view: list of cards, click to render markdown (or open HTML iframe). */

const Docs = {
  registry: [],

  async init() {
    const data = await API.getDocsList();
    this.registry = data.docs || [];
    this.renderList();

    document.getElementById('docsBack').addEventListener('click', () => this.showList());
  },

  renderList() {
    const el = document.getElementById('docsList');
    const icons = {
      'how-it-works': '\u25B6',
      'architecture': '\u26C0',
      'test-scenario-design': '\u2261',
      'threat-model': '\u26E8',
    };
    el.innerHTML = this.registry.map(d => `
      <div class="docs-card" data-doc-id="${d.id}">
        <div class="ic">${icons[d.id] || '\u2014'}</div>
        <div class="ttl">${esc(d.title)}</div>
        <div class="sub">${esc(d.subtitle)}</div>
      </div>
    `).join('');
    el.querySelectorAll('.docs-card').forEach(c => {
      c.addEventListener('click', () => this.open(c.dataset.docId));
    });
  },

  async open(id) {
    const entry = this.registry.find(d => d.id === id);
    if (!entry) return;

    document.getElementById('docsList').hidden = true;
    document.getElementById('docsReader').hidden = false;
    document.getElementById('docsTitle').textContent = entry.title;

    const contentEl = document.getElementById('docsContent');
    const iframeEl = document.getElementById('docsIframe');

    if (entry.type === 'html') {
      contentEl.hidden = true;
      iframeEl.hidden = false;
      iframeEl.src = `/docs/${entry.id}`;
      return;
    }

    iframeEl.hidden = true;
    contentEl.hidden = false;
    contentEl.innerHTML = '<p style="color: var(--muted);">Loading\u2026</p>';

    const md = await API.getDocContent(entry.id);
    contentEl.innerHTML = renderMarkdown(md);

    if (window.mermaid) {
      try {
        mermaid.initialize({ startOnLoad: false, theme: 'default', securityLevel: 'loose' });
        await mermaid.run({ querySelector: '.mermaid' });
      } catch (e) {
        console.warn('mermaid render', e);
      }
    }
  },

  showList() {
    document.getElementById('docsList').hidden = false;
    document.getElementById('docsReader').hidden = true;
    document.getElementById('docsIframe').src = 'about:blank';
  },
};

function renderMarkdown(md) {
  if (!window.marked) return `<pre>${esc(md)}</pre>`;

  // Pre-extract mermaid fenced blocks so marked doesn't escape them.
  const mermaidBlocks = [];
  md = md.replace(/```mermaid\n([\s\S]*?)```/g, (m, code) => {
    mermaidBlocks.push(code);
    return `\n@@MERMAID_${mermaidBlocks.length - 1}@@\n`;
  });

  marked.setOptions({ gfm: true, breaks: false });
  let html = marked.parse(md);

  // Reinsert mermaid blocks as <div class="mermaid">.
  html = html.replace(/<p>@@MERMAID_(\d+)@@<\/p>/g, (m, i) => {
    return `<div class="mermaid">${escForMermaid(mermaidBlocks[+i])}</div>`;
  });
  html = html.replace(/@@MERMAID_(\d+)@@/g, (m, i) => {
    return `<div class="mermaid">${escForMermaid(mermaidBlocks[+i])}</div>`;
  });
  return html;
}

function escForMermaid(s) {
  // mermaid.run reads textContent so just leave it as text.
  return esc(s);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}
