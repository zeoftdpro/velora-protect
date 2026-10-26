const SEV = {critical: 'Critique', high: 'Élevé', medium: 'Moyen', low: 'Faible', info: 'Info'};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c != null && c !== false) node.append(c.nodeType ? c : document.createTextNode(String(c)));
  return node;
}

let toastTimer;
function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 5000);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString('fr-FR', {dateStyle: 'short', timeStyle: 'short'});
}
function fmtSize(n) {
  if (n == null) return '';
  const u = ['o', 'Ko', 'Mo', 'Go']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}
function pct(x) { return Math.round(x * 100) + ' %'; }

function findingItem(f) {
  return el('li', {},
    el('span', {class: 'pill sev-' + f.severity}, SEV[f.severity] || f.severity), ' ',
    el('span', {class: 'finding-title'}, f.title),
    f.file ? el('div', {class: 'mono muted'}, f.file + (f.line ? ':' + f.line : '')) : null,
    f.detail ? el('div', {class: 'small'}, f.detail) : null,
    f.fix ? el('div', {class: 'small muted'}, '→ ' + f.fix) : null);
}

// --------------------------------------------------------------------------- analyse express

const CATEGORIES = {malware: 'Code malveillant', secret: 'Secrets', exposure: 'Exposé au public', live: 'Site en ligne', web: 'Sécurité web',
  mobile: 'Mobile', dependency: 'Dépendances', config: 'Configuration'};
// Dossiers inutiles à l'analyse (dépendances installées, caches) : ils ne sont pas envoyés.
const SKIP_DIRS = new Set(['.git', '.hg', '.svn', '.velora', 'node_modules', 'bower_components', 'vendor', '__pycache__',
  '.venv', 'venv', '.tox', '.mypy_cache', '.pytest_cache', '.idea', '.gradle', '.nuxt', '.svelte-kit', '.turbo',
  '.cache', '.parcel-cache', 'coverage', '.terraform', '.dart_tool', 'Pods', '.expo']);
const MAX_FILE = 8 * 1024 * 1024, MAX_TOTAL = 190 * 1024 * 1024, MAX_COUNT = 20000;

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// Archive ZIP sans compression (méthode « stored ») : aucune bibliothèque nécessaire.
async function buildZip(files) {
  const enc = new TextEncoder(), parts = [], central = [];
  const dosDate = ((new Date().getFullYear() - 1980) << 9) | (1 << 5) | 1;
  let offset = 0, centralSize = 0;
  for (const {path, file} of files) {
    const name = enc.encode(path), data = new Uint8Array(await file.arrayBuffer()), crc = crc32(data);
    const local = new DataView(new ArrayBuffer(30));
    local.setUint32(0, 0x04034b50, true); local.setUint16(4, 20, true); local.setUint16(6, 0x0800, true);
    local.setUint16(12, dosDate, true); local.setUint32(14, crc, true);
    local.setUint32(18, data.length, true); local.setUint32(22, data.length, true); local.setUint16(26, name.length, true);
    parts.push(local, name, data);
    const cen = new DataView(new ArrayBuffer(46));
    cen.setUint32(0, 0x02014b50, true); cen.setUint16(4, 20, true); cen.setUint16(6, 20, true); cen.setUint16(8, 0x0800, true);
    cen.setUint16(14, dosDate, true); cen.setUint32(16, crc, true); cen.setUint32(20, data.length, true);
    cen.setUint32(24, data.length, true); cen.setUint16(28, name.length, true); cen.setUint32(42, offset, true);
    central.push(cen, name);
    offset += 30 + name.length + data.length;
    centralSize += 46 + name.length;
  }
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true);
  end.setUint32(12, centralSize, true); end.setUint32(16, offset, true);
  return new Blob([...parts, ...central, end], {type: 'application/zip'});
}

function keepPath(path) { return !path.split('/').slice(0, -1).some(d => SKIP_DIRS.has(d)); }

// À appeler de façon synchrone dans l'événement drop : DataTransfer n'est plus lisible ensuite.
function entriesFromDrop(dt) {
  return [...dt.items].filter(i => i.kind === 'file').map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
}
async function filesFromEntries(entries) {
  const out = [];
  async function walk(entry, prefix) {
    if (entry.isFile) {
      out.push({path: prefix + entry.name, file: await new Promise((res, rej) => entry.file(res, rej))});
      return;
    }
    if (SKIP_DIRS.has(entry.name)) return;
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
      if (!batch.length) break;
      for (const e of batch) await walk(e, prefix + entry.name + '/');
    }
  }
  for (const e of entries) await walk(e, '');
  return out;
}

function selectFiles(files) {
  const kept = [];
  let total = 0, tooBig = 0;
  for (const f of files) {
    if (!keepPath(f.path)) continue;
    if (f.file.size > MAX_FILE) { tooBig++; continue; }
    if (kept.length >= MAX_COUNT || total + f.file.size > MAX_TOTAL) throw new Error('Projet trop volumineux : envoyez une archive .zip sans les dépendances ni les médias.');
    kept.push(f); total += f.file.size;
  }
  if (!kept.length) throw new Error('Aucun fichier à analyser.');
  return {kept, tooBig};
}


function scoreClass(score) { return score >= 80 ? 'ok' : score >= 50 ? 'warn' : 'bad'; }

function snippetBlock(s) {
  const pre = el('pre', {class: 'snippet'}, s.content);
  const copy = el('button', {class: 'small', onclick: async () => {
    try { await navigator.clipboard.writeText(s.content); toast('Copié : ' + s.filename); }
    catch { toast('Copie impossible : sélectionnez le texte à la main.'); }
  }}, 'Copier');
  return el('div', {}, el('div', {class: 'row', style: 'margin:8px 0 0;justify-content:space-between'},
    el('span', {}, el('strong', {}, s.label), ' ', el('span', {class: 'mono muted'}, s.filename)), copy), pre);
}

// Indice de confiance /100 : fiabilité du score (langages couverts, dépendances vérifiées, fichiers lus).
function confidenceBlock(c) {
  if (!c) return null;
  return el('details', {class: 'confidence'},
    el('summary', {}, `Pourquoi une confiance de ${c.score}/100 ?`),
    el('ul', {class: 'list small'}, c.factors.map(f => el('li', {},
      el('strong', {}, `${f.label} : ${f.points}/${f.max}`), el('div', {class: 'muted'}, f.detail)))),
    el('p', {class: 'small muted', style: 'margin:4px 0 0'}, c.note));
}

const SCORE_COLOR = {ok: 'var(--ok)', warn: 'var(--warn)', bad: 'var(--bad)'};

// Jauge circulaire /100.
function gauge(value, label, sub) {
  return el('div', {class: 'gauge', role: 'img', 'aria-label': `${label} : ${value} sur 100`,
    style: `--v:${value};--c:${SCORE_COLOR[scoreClass(value)]}`},
    el('div', {}, el('strong', {}, value), el('span', {}, label), sub ? el('em', {}, sub) : null));
}

// En-tête d'un rapport : jauges Sécurité / Confiance et verdict « code malveillant » bien visibles.
function scoreHeader(r, isLive) {
  const malware = (r.findings || []).filter(f => f.category === 'malware');
  return el('div', {class: 'gauges'},
    gauge(r.score, 'Sécurité'),
    !isLive && r.confidence ? gauge(r.confidence.score, 'Confiance', r.confidence.level) : null,
    isLive ? null : el('div', {class: 'shield ' + (malware.length ? 'bad' : 'ok')},
      el('strong', {}, malware.length ? `⚠ ${malware.length} élément(s) malveillant(s)` : '✔ Aucun code malveillant'),
      el('span', {}, malware.length ? 'Porte dérobée, mineur, script piégé… détails ci-dessous.'
        : 'Ni porte dérobée, ni webshell, ni mineur, ni script d\'installation piégé détecté.')));
}

function reportCard(r, kind) {
  const isLive = kind === 'live';
  const title = isLive ? (r.final_url || r.url) : (r.upload?.name || 'Projet');
  const meta = isLive
    ? [r.info?.tls_version, r.info?.cert_expires ? `certificat valable jusqu'au ${r.info.cert_expires}` : null,
       r.info?.server, `${r.requests} requêtes · ${r.duration} s`].filter(Boolean).join(' · ')
    : `${r.files_scanned} fichiers · ${r.dependencies} dépendances · ${r.duration} s` + (r.dependencies && !r.network_checked ? ' · dépendances non vérifiées' : '');
  const groups = {};
  for (const f of r.findings) (groups[f.category] = groups[f.category] || []).push(f);
  const order = Object.keys(CATEGORIES).filter(c => groups[c]).concat(Object.keys(groups).filter(c => !CATEGORIES[c]));
  return el('section', {class: 'card report'},
    el('h3', {}, (isLive ? 'Site : ' : 'Code : ') + title),
    el('div', {class: 'small muted'}, meta),
    scoreHeader(r, isLive),
    isLive ? null : confidenceBlock(r.confidence),
    (r.stack || []).length ? el('div', {}, ...r.stack.map(s => el('span', {class: 'chip'}, s))) : null,
    ...(r.warnings || []).map(w => el('p', {class: 'small warn'}, '⚠ ' + w)),
    ...(r.info?.notes || []).map(w => el('p', {class: 'small muted'}, '· ' + w)),
    r.findings.length ? null : el('p', {class: 'ok'}, '✔ Aucun problème détecté.'),
    ...order.map(cat => el('details', {open: groups[cat].some(f => ['critical', 'high'].includes(f.severity))},
      el('summary', {}, `${CATEGORIES[cat] || cat} (${groups[cat].length})`),
      el('ul', {class: 'list'}, groups[cat].map(findingItem)))),
    (r.hardening || []).length ? el('details', {},
      el('summary', {}, 'Configuration de sécurité à copier'),
      el('p', {class: 'small muted'}, 'En-têtes HTTP recommandés pour votre hébergement. La Content-Security-Policy est stricte : '
        + 'testez-la d\'abord en « Content-Security-Policy-Report-Only ».'),
      ...r.hardening.map(snippetBlock)) : null,
    (r.recommendations || []).length ? el('details', {}, el('summary', {}, 'Recommandations anti-copie'),
      el('ul', {class: 'small'}, r.recommendations.map(x => el('li', {}, x)))) : null);
}

// Bloc « Analyse express » : glisser-déposer d'un projet et/ou adresse d'un site en ligne.
// analyseProject(blob, {offline, progress}) et analyseSite(url, {progress}) renvoient un rapport.
// siteExtra : éléments affichés sous le champ d'adresse (options propres à l'interface).
function mountQuick(target, {intro, analyseProject, analyseSite, siteExtra = null}) {
  const results = el('div', {class: 'reports'});
  const progress = el('div', {class: 'progress', role: 'status'});
  const setProgress = msg => { progress.textContent = msg; };
  const url = el('input', {type: 'url', placeholder: 'https://mon-site.fr (optionnel)', style: 'flex:1;min-width:220px',
    'aria-label': 'Adresse du site en ligne'});
  const offline = el('input', {type: 'checkbox', id: 'quickOffline'});
  const dirInput = el('input', {type: 'file', webkitdirectory: true, multiple: true, hidden: true});
  const zipInput = el('input', {type: 'file', accept: '.zip,application/zip', hidden: true});
  const drop = el('div', {class: 'drop'},
    el('strong', {}, 'Glissez ici le dossier de votre site ou de votre application'),
    el('div', {class: 'small muted'}, 'ou une archive .zip. Toutes technologies : React, Vue, PHP, Python, HTML/CSS, C/C++, '
      + 'Android, iOS, Flutter… Les dépendances (node_modules, vendor) sont ignorées.'),
    el('div', {class: 'row'}, el('button', {onclick: () => dirInput.click()}, 'Choisir un dossier'),
      el('button', {onclick: () => zipInput.click()}, 'Choisir un .zip')));
  const liveBtn = el('button', {class: 'primary'}, 'Tester le site');

  let busy = false;
  async function analyse(getProject) {
    if (busy) return toast('Une analyse est déjà en cours.');
    if (!getProject && !url.value.trim()) return toast('Glissez un projet ou saisissez l\'adresse d\'un site.');
    busy = true; liveBtn.disabled = true;
    results.replaceChildren();
    const jobs = [];
    if (getProject) jobs.push((async () => {
      setProgress('Préparation du projet…');
      const {blob, note} = await getProject();
      setProgress(`Analyse du code (${fmtSize(blob.size)})…` + (note ? ' ' + note : ''));
      results.append(reportCard(await analyseProject(blob, {offline: offline.checked, progress: setProgress}), 'code'));
    })());
    if (url.value.trim()) jobs.push((async () => {
      results.append(reportCard(await analyseSite(url.value.trim(), {progress: setProgress}), 'live'));
    })());
    try {
      const outcome = await Promise.allSettled(jobs);
      outcome.filter(o => o.status === 'rejected').forEach(o => toast('⚠ ' + o.reason.message));
    } finally { setProgress(''); busy = false; liveBtn.disabled = false; }
  }

  async function fromFiles(files) {
    if (files.length === 1 && /\.zip$/i.test(files[0].path)) return {blob: files[0].file, note: ''};
    const {kept, tooBig} = selectFiles(files);
    return {blob: await buildZip(kept), note: tooBig ? `(${tooBig} fichier(s) de plus de 8 Mo ignoré(s))` : ''};
  }

  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('drag'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag'));
  drop.addEventListener('drop', e => {
    e.preventDefault(); drop.classList.remove('drag');
    const entries = entriesFromDrop(e.dataTransfer);
    const plain = [...e.dataTransfer.files];
    analyse(async () => fromFiles(entries.length ? await filesFromEntries(entries) : plain.map(f => ({path: f.name, file: f}))));
  });
  dirInput.addEventListener('change', () => {
    const files = [...dirInput.files].map(f => ({path: f.webkitRelativePath || f.name, file: f}));
    dirInput.value = '';
    if (files.length) analyse(() => fromFiles(files));
  });
  zipInput.addEventListener('change', () => {
    const file = zipInput.files[0]; zipInput.value = '';
    if (file) analyse(async () => ({blob: file, note: ''}));
  });
  liveBtn.addEventListener('click', () => analyse(null));
  url.addEventListener('keydown', e => { if (e.key === 'Enter') analyse(null); });

  target.replaceChildren(el('section', {class: 'card'},
    el('h2', {}, 'Analyse express'),
    el('p', {class: 'sub'}, intro),
    drop, dirInput, zipInput,
    el('div', {class: 'row'}, url, liveBtn,
      el('label', {for: 'quickOffline', style: 'margin:0;display:flex;gap:6px;align-items:center'}, offline, 'sans OSV.dev')),
    siteExtra, progress, results));
  return {url};
}
