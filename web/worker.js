// Moteur d'analyse Velora exécuté dans le navigateur (Python compilé en WebAssembly via Pyodide).
// Le code du client reste dans ce worker : il n'est jamais envoyé à un serveur. Seuls les noms et
// versions des dépendances partent vers la base publique OSV.dev (sauf option « sans OSV.dev »).
const PYODIDE_URL = 'https://cdn.jsdelivr.net/pyodide/v0.29.5/full/';
importScripts(PYODIDE_URL + 'pyodide.js');

const BOOT = `
import json, os, shutil, sys
sys.path.insert(0, "/engine")
from js import XMLHttpRequest
from velora import VeloraError
from velora.core import net, upload

def _request(url, data=None, headers=None, timeout=30, max_bytes=20 * 1024 * 1024):
    # urllib ne fonctionne pas dans le navigateur : XHR synchrone (autorisé dans un worker).
    xhr = XMLHttpRequest.new()
    xhr.open("POST" if data is not None else "GET", url, False)
    for key, value in (headers or {}).items():
        if key.lower() != "user-agent":
            xhr.setRequestHeader(key, value)
    try:
        xhr.send(data.decode("utf-8") if data is not None else None)
    except Exception as e:
        raise net.NetworkError(f"{url} : {e}")
    if xhr.status == 0 or xhr.status >= 400:
        raise net.NetworkError(f"{url} : HTTP {xhr.status}")
    return xhr.responseText.encode("utf-8")[:max_bytes]

net.request = _request

def run_upload(path, offline):
    from velora.scan import scan_uploaded
    work = "/tmp/projet"
    shutil.rmtree(work, ignore_errors=True)
    try:
        stats = upload.safe_extract(path, work)
        root = upload.project_root(work)
        report = scan_uploaded(root, network=not offline, blocked=stats["blocked"])
        return json.dumps({**report, "upload": {**stats, "name": root.name}}, ensure_ascii=False, default=str)
    except VeloraError as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if os.path.exists(path):
            os.remove(path)
`;

let ready = null;
function boot(id) {
  if (!ready) {
    ready = (async () => {
      postMessage({id, progress: 'Chargement du moteur d\'analyse (une dizaine de Mo la première fois)…'});
      const py = await loadPyodide({indexURL: PYODIDE_URL});
      const engine = await fetch('/engine.zip');
      if (!engine.ok) throw new Error('moteur introuvable');
      py.unpackArchive(await engine.arrayBuffer(), 'zip', {extractDir: '/engine'});
      py.runPython(BOOT);
      return py;
    })();
    ready.catch(() => { ready = null; });
  }
  return ready;
}

onmessage = async e => {
  const {id, zip, offline} = e.data;
  try {
    const py = await boot(id);
    postMessage({id, progress: 'Analyse du code dans votre navigateur…'});
    py.FS.writeFile('/tmp/envoi.zip', new Uint8Array(zip));
    const out = JSON.parse(py.globals.get('run_upload')('/tmp/envoi.zip', !!offline));
    if (out.error) postMessage({id, error: out.error});
    else postMessage({id, result: out});
  } catch (err) {
    postMessage({id, error: 'Analyse impossible : ' + String(err && err.message || err).split('\n').filter(Boolean).pop()});
  }
};
