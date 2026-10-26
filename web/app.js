// Velora en ligne : l'analyse du code tourne dans le navigateur (worker.js), le test de site sur le serveur.

let worker = null, nextId = 0;
const pending = new Map();

function engine() {
  if (!worker) {
    worker = new Worker('/worker.js');
    worker.onmessage = e => {
      const {id, result, error, progress} = e.data;
      const job = pending.get(id);
      if (!job) return;
      if (progress) return job.progress(progress);
      pending.delete(id);
      if (error) job.reject(new Error(error)); else job.resolve(result);
    };
    worker.onerror = e => {
      for (const job of pending.values()) job.reject(new Error('Moteur d\'analyse indisponible' + (e.message ? ' : ' + e.message : '')));
      pending.clear();
      worker = null;
    };
  }
  return worker;
}

async function analyseInBrowser(blob, {offline, progress}) {
  const buffer = await blob.arrayBuffer();
  return new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, {resolve, reject, progress});
    engine().postMessage({id, zip: buffer, offline}, [buffer]);
  });
}

async function post(path, body) {
  const res = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
  const data = await res.json().catch(() => ({error: 'Réponse invalide du serveur (' + res.status + ')'}));
  if (!res.ok) throw new Error(data.error || ('Erreur ' + res.status));
  return data;
}

// --------------------------------------------------------------------------- preuve de propriété

const deep = el('input', {type: 'checkbox', id: 'deep'});
const verifyBox = el('div', {class: 'verify', hidden: true});
let quick = null;

function copyButton(text) {
  return el('button', {class: 'small', onclick: async () => {
    try { await navigator.clipboard.writeText(text); toast('Copié'); } catch { toast('Copie impossible : sélectionnez le texte.'); }
  }}, 'Copier');
}

async function showInstructions() {
  const url = quick?.url.value.trim();
  if (!deep.checked) { verifyBox.hidden = true; return; }
  verifyBox.hidden = false;
  if (!url) { verifyBox.replaceChildren(el('p', {class: 'small muted'}, 'Saisissez d\'abord l\'adresse du site.')); return; }
  verifyBox.replaceChildren(el('p', {class: 'small muted'}, 'Préparation du jeton…'));
  try {
    const v = await post('/api/verify', {url});
    const check = el('button', {onclick: async () => {
      check.disabled = true;
      try {
        const r = await post('/api/verify', {url, check: true});
        toast(r.verified ? `✔ Propriété vérifiée (${r.method === 'dns' ? 'DNS' : 'fichier'}) : lancez le test.`
                         : 'Jeton introuvable pour l\'instant (le DNS peut mettre quelques minutes à se propager).');
      } catch (e) { toast('⚠ ' + e.message); } finally { check.disabled = false; }
    }}, 'Vérifier maintenant');
    verifyBox.replaceChildren(
      el('p', {class: 'small'}, `Prouvez que ${v.host} vous appartient avec l'une de ces deux méthodes :`),
      el('div', {class: 'small'}, el('strong', {}, '1. Fichier'), ' — publiez ', el('span', {class: 'mono'}, v.file.url),
        ' contenant :'),
      el('div', {class: 'row'}, el('code', {class: 'mono'}, v.file.content), copyButton(v.file.content)),
      el('div', {class: 'small'}, el('strong', {}, '2. DNS'), ' — enregistrement TXT ', el('span', {class: 'mono'}, v.dns.name),
        ' :'),
      el('div', {class: 'row'}, el('code', {class: 'mono'}, v.dns.value), copyButton(v.dns.value)),
      el('div', {class: 'row'}, check));
  } catch (e) {
    verifyBox.replaceChildren(el('p', {class: 'small bad'}, e.message));
  }
}

deep.addEventListener('change', showInstructions);

quick = mountQuick(document.getElementById('quick'), {
  intro: 'Votre code est analysé dans votre navigateur : il n\'est jamais envoyé sur nos serveurs. Le test en ligne ne fait '
    + 'que des lectures, comme un visiteur : HTTPS, certificat, en-têtes de sécurité, cookies, CORS, scripts publiés.',
  analyseProject: analyseInBrowser,
  analyseSite: async (url, {progress}) => {
    progress('Test du site en ligne…');
    return post('/api/live', {url, deep: deep.checked});
  },
  siteExtra: el('div', {},
    el('label', {for: 'deep', style: 'display:flex;gap:6px;align-items:center;margin:4px 0'}, deep,
      'Analyse approfondie : rechercher les fichiers exposés (/.env, /.git, sauvegardes…) — sites qui vous appartiennent'),
    verifyBox),
});
quick.url.addEventListener('change', showInstructions);
