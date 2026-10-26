"""Interface en ligne de commande : « velora <commande> »."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from velora import VeloraError, __version__
from velora.core import config as cfgmod
from velora.core import gitutil, history, notify
from velora.core import term as t
from velora.core.config import Project
from velora.scan.models import at_least


def _project(args) -> Project:
    root = Path(args.project) if args.project else cfgmod.find_project_root(Path.cwd())
    if not root.is_dir():
        raise VeloraError(f"Dossier introuvable : {root}")
    return Project(root)


def _print_findings(findings, limit: int | None = None) -> None:
    shown = findings[:limit] if limit else findings
    for f in shown:
        where = t.c(f.location, "grey") if f.location else ""
        print(f"  {t.severity(f.severity)} {f.title}  {where}")
        if f.detail:
            print(f"      {f.detail}")
        if f.fix:
            print(t.c(f"      → {f.fix}", "grey"))
    if limit and len(findings) > limit:
        print(t.c(f"  … et {len(findings) - limit} autre(s) (--all pour tout afficher, --json pour exporter)", "grey"))


# --------------------------------------------------------------------------- init / config / status

def cmd_init(args) -> int:
    project = Project(Path(args.project or Path.cwd()))
    if not project.initialized:
        project.config["project_name"] = args.name or project.root.name
    if args.author:
        project.config["author"] = args.author
    if args.backup_dest:
        dests = project.config["backup"]["destinations"]
        for d in args.backup_dest:
            if d not in dests:
                dests.append(d)
    if args.webhook:
        project.config["alerts"]["webhook_url"] = args.webhook
    project.save_config()
    cfgmod.register_project(project.root)
    t.ok(f"Projet « {project.name} » initialisé ({project.state_dir})")
    if not project.config["author"]:
        t.warn('Auteur non renseigné : velora config set author "Votre nom"  (utilisé pour les preuves et licences)')
    if not project.config["backup"]["destinations"]:
        t.warn('Aucune destination de sauvegarde : velora config add backup.destinations "E:\\Sauvegardes"')
    print("\nÉtapes suivantes :")
    print("  velora scan             analyser la sécurité du projet")
    print("  velora backup run       faire une première sauvegarde")
    print("  velora proof create     horodater le code (preuve d'antériorité)")
    print("  velora hook install     bloquer les commits contenant des secrets")
    print("  velora ui               ouvrir le tableau de bord")
    return 0


def _walk_key(conf: dict, dotted: str, create: bool = False):
    parts = dotted.split(".")
    node = conf
    for p in parts[:-1]:
        if p not in node or not isinstance(node[p], dict):
            if not create:
                raise VeloraError(f"Clé inconnue : {dotted}")
            node[p] = {}
        node = node[p]
    return node, parts[-1]


def _parse_value(raw: str):
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def cmd_config(args) -> int:
    project = _project(args)
    if args.action == "show":
        print(json.dumps(project.config, indent=2, ensure_ascii=False))
        return 0
    if not args.key:
        raise VeloraError("Précisez une clé, ex. : velora config set author \"Ada Lovelace\"")
    node, leaf = _walk_key(project.config, args.key, create=args.action == "set")
    if args.action == "get":
        print(json.dumps(node.get(leaf), indent=2, ensure_ascii=False))
        return 0
    if args.value is None:
        raise VeloraError("Valeur manquante.")
    value = _parse_value(args.value) if args.action == "set" else args.value
    if args.action == "set":
        node[leaf] = value
    else:
        current = node.setdefault(leaf, [])
        if not isinstance(current, list):
            raise VeloraError(f"{args.key} n'est pas une liste")
        if args.action == "add" and value not in current:
            current.append(value)
        elif args.action == "remove":
            if value not in current:
                raise VeloraError(f"« {value} » absent de {args.key}")
            current.remove(value)
    project.save_config()
    cfgmod.register_project(project.root)
    t.ok(f"{args.key} = {json.dumps(node[leaf], ensure_ascii=False)}")
    return 0


def project_status(project: Project) -> dict:
    from velora import proof
    from velora.scan import last_scan
    scan = last_scan(project)
    backup_ok = history.last(project, "backup", status="ok")
    backup_last = history.last(project, "backup")
    proofs = proof.list_proofs(project)
    return {
        "name": project.name, "root": str(project.root), "initialized": project.initialized,
        "author": project.config.get("author"),
        "scan": scan and {k: scan[k] for k in ("time", "score", "counts", "files_scanned", "dependencies")},
        "backup": {"last_ok": backup_ok, "last": backup_last,
                   "destinations": project.config["backup"]["destinations"]},
        "proofs": {"count": len(proofs), "last": proofs[0] if proofs else None},
        "fingerprints": (project.path("fingerprints.json").exists()),
        "license": (project.root / "LICENSE").exists() or (project.root / "LICENSE.md").exists(),
        "git": gitutil.is_repo(project.root),
        "hook": (project.root / ".git" / "hooks" / "pre-commit").exists()
                and "velora" in (project.root / ".git" / "hooks" / "pre-commit").read_text(errors="replace"),
    }


def cmd_status(args) -> int:
    project = _project(args)
    st = project_status(project)
    if args.json:
        print(json.dumps(st, indent=2, ensure_ascii=False))
        return 0
    t.title(f"Velora · {st['name']}  {t.c(st['root'], 'grey')}")
    if not st["initialized"]:
        t.warn("Projet non initialisé : velora init")
    scan = st["scan"]
    if scan:
        color = "green" if scan["score"] >= 80 else "yellow" if scan["score"] >= 50 else "red"
        counts = ", ".join(f"{n} {t.SEVERITY_LABELS[s].lower()}" for s, n in scan["counts"].items()) or "aucun problème"
        print(f"  Sécurité     score {t.c(scan['score'], color, 'bold')}/100 — {counts} ({scan['time'][:16]})")
    else:
        print(f"  Sécurité     {t.c('jamais analysé', 'yellow')} → velora scan")
    b = st["backup"]["last_ok"]
    if b:
        print(f"  Sauvegarde   {b['archive']} ({b['time'][:16]}) → {len(b.get('destinations') or {})} destination(s)")
    else:
        print(f"  Sauvegarde   {t.c('aucune', 'yellow')} → velora backup run")
    if st["backup"]["last"] and st["backup"]["last"].get("status") == "failed":
        print(t.c(f"               dernière tentative en échec : {st['backup']['last'].get('message')}", "red"))
    p = st["proofs"]
    print(f"  Preuves      {p['count']} horodatage(s)" + (f", dernier : {p['last']['id']}" if p["last"] else
                                                          f" {t.c('→ velora proof create', 'yellow')}"))
    print(f"  Protection   LICENSE {'✔' if st['license'] else '✖'}   empreintes anti-copie "
          f"{'✔' if st['fingerprints'] else '✖'}   hook anti-secrets {'✔' if st['hook'] else '✖'}")
    return 0


# --------------------------------------------------------------------------- scan

def cmd_scan(args) -> int:
    from velora.scan import run_scan
    project = _project(args)
    network = False if args.offline else None
    result = run_scan(project, network=network, staged=args.staged, save=not args.staged)
    threshold = args.fail_on or project.config["scan"].get("fail_on", "high")
    blocking = [f for f in result.findings if at_least(f.severity, threshold)]

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    elif args.staged:
        if blocking:
            t.err(f"Commit bloqué par Velora : {len(blocking)} secret(s) dans les fichiers indexés")
            _print_findings(blocking)
            print(t.c("  Retirez-les, ou ajoutez « velora:ignore » en commentaire sur la ligne s'il s'agit d'un "
                      "faux positif. (Contournement ponctuel : git commit --no-verify)", "grey"))
    else:
        t.title(f"Analyse de sécurité · {project.name}")
        print(t.c(f"  {result.files_scanned} fichiers, {result.dependencies} dépendances, {result.duration:.1f} s", "grey"))
        if result.stack:
            print(t.c(f"  Technologies : {', '.join(result.stack)}", "grey"))
        for w in result.warnings:
            t.warn(w)
        if result.findings:
            print()
            _print_findings(result.findings, None if args.all else 25)
        score = result.score
        color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        print(f"\n  Score de sécurité : {t.c(f'{score}/100', color, 'bold')}")
        conf = result.confidence
        if conf:
            ccolor = "green" if conf["score"] >= 80 else "yellow" if conf["score"] >= 50 else "red"
            print(f"  Confiance de l'analyse : {t.c(str(conf['score']) + '/100', ccolor, 'bold')} ({conf['level']})")
            for factor in conf["factors"]:
                if factor["points"] < factor["max"]:
                    print(t.c(f"    − {factor['label']} {factor['points']}/{factor['max']} : {factor['detail']}", "grey"))
        if not result.findings:
            t.ok("Aucun problème détecté.")
    if args.alert and blocking:
        notify.send_alert(project, f"{len(blocking)} problème(s) de sécurité",
                          "\n".join(f"- [{f.severity}] {f.title} {f.location}" for f in blocking[:10]))
    return 1 if blocking else 0


def cmd_web(args) -> int:
    from velora.scan import hardening, live
    result = live.scan(args.url, allow_private=args.allow_private,
                       log=(lambda m: None) if args.json else (lambda m: t.info(m)))
    threshold = args.fail_on or "high"
    blocking = [f for f in result.findings if at_least(f.severity, threshold)]
    if args.json:
        print(json.dumps({**result.to_dict(), "hardening": hardening.suggest(platforms=result.platforms)},
                         indent=2, ensure_ascii=False))
        return 1 if blocking else 0
    t.title(f"Site en ligne · {result.final_url}")
    info = result.info
    details = [info.get("tls_version"), info.get("cert_expires") and f"certificat jusqu'au {info['cert_expires']}",
               info.get("server"), f"{result.requests} requêtes, {result.duration:.1f} s"]
    print(t.c("  " + " · ".join(d for d in details if d), "grey"))
    for note in info.get("notes", []):
        t.warn(note)
    if result.findings:
        print()
        _print_findings(result.findings)
    score = result.score
    color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    print(f"\n  Score de sécurité : {t.c(f'{score}/100', color, 'bold')}")
    print(t.c(f"  Plateforme détectée : {', '.join(result.platforms) or 'inconnue'} — configuration à copier : "
              "velora harden" + "".join(f" --platform {p}" for p in result.platforms if p in hardening.PLATFORMS), "grey"))
    return 1 if blocking else 0


def cmd_harden(args) -> int:
    from velora.scan import hardening
    stack = []
    if not args.platform:
        from velora.scan import run_scan
        stack = run_scan(_project(args), network=False, save=False).stack
    for s in hardening.suggest(platforms=args.platform or [], stack=stack):
        t.title(f"{s['label']}  {t.c(s['filename'], 'grey')}")
        print(s["content"])
    print()
    t.info(hardening.CSP_NOTE)
    return 0


HOOK_SCRIPT = """#!/bin/sh
# velora: blocage des secrets avant commit (installé par « velora hook install »)
PYTHONPATH="{pkg_parent}${{PYTHONPATH:+{sep}$PYTHONPATH}}" "{python}" -m velora -C "$(git rev-parse --show-toplevel)" scan --staged --fail-on high
"""


def cmd_hook(args) -> int:
    project = _project(args)
    hooks = project.root / ".git" / "hooks"
    if not hooks.parent.exists():
        raise VeloraError("Ce projet n'est pas un dépôt git (git init).")
    hook = hooks / "pre-commit"
    if args.action == "uninstall":
        if hook.exists() and "velora" in hook.read_text(errors="replace"):
            hook.unlink()
            t.ok("Hook pre-commit retiré.")
        return 0
    if hook.exists() and "velora" not in hook.read_text(errors="replace"):
        raise VeloraError(f"Un hook pre-commit existe déjà ({hook}) : ajoutez-y manuellement "
                          "« python -m velora scan --staged ».")
    hooks.mkdir(parents=True, exist_ok=True)
    pkg_parent = Path(__file__).resolve().parent.parent.as_posix()
    hook.write_text(HOOK_SCRIPT.format(python=Path(sys.executable).as_posix(), pkg_parent=pkg_parent,
                                       sep=";" if os.name == "nt" else ":"), encoding="utf-8", newline="\n")
    hook.chmod(0o755)
    t.ok("Hook pre-commit installé : les commits contenant des secrets seront bloqués.")
    return 0


# --------------------------------------------------------------------------- backup

def cmd_backup(args) -> int:
    from velora import backup
    project = _project(args)

    if args.action == "run":
        t.title(f"Sauvegarde · {project.name}")
        result = backup.run_backup(project, force=args.force, log=lambda m: t.info(m))
        if result.status == "skipped":
            t.ok(result.message + " (--force pour sauvegarder quand même)")
            return 0
        t.ok(f"{result.archive} — {result.files} fichiers, {t.human_size(result.size)}"
             + (f", {result.pruned} ancienne(s) archive(s) supprimée(s)" if result.pruned else ""))
        if result.status == "partial":
            t.warn(result.message)
            return 1
        return 0

    if args.action == "list":
        for entry in backup.list_backups(project):
            t.title(entry["destination"])
            if entry.get("error"):
                t.err(entry["error"])
            for a in entry["archives"]:
                size = t.human_size(a["size"]) if "size" in a else ""
                print(f"  {a['name']}  {t.c(size, 'grey')}")
            if not entry["archives"] and not entry.get("error"):
                print(t.c("  (aucune archive)", "grey"))
        return 0

    if args.action == "check":
        ok, msg = backup.check_freshness(project)
        (t.ok if ok else t.err)(msg)
        return 0 if ok else 1

    if not args.archive:
        raise VeloraError("Précisez l'archive : un chemin, un nom, ou « latest ».")
    with tempfile.TemporaryDirectory(prefix="velora-") as tmp:
        archive = backup.resolve_archive(project, args.archive, Path(tmp))
        if args.action == "verify":
            ok, problems = backup.verify_archive(archive)
            if ok:
                t.ok(f"Archive intègre : {archive.name}")
                return 0
            t.err(f"Archive endommagée : {archive.name}")
            for p in problems[:20]:
                print(f"  - {p}")
            return 1
        if args.action == "restore":
            if not args.target:
                raise VeloraError("Précisez le dossier de restauration : velora backup restore latest D:\\Restauration")
            n = backup.restore_archive(archive, Path(args.target))
            t.ok(f"{n} fichiers restaurés dans {Path(args.target).resolve()}")
            print(t.c("  Historique git : git clone _velora_restore/git/repo.bundle ; bases : _velora_restore/databases/",
                      "grey"))
            return 0
    return 0


def cmd_schedule(args) -> int:
    project = _project(args)
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    steps = ["backup run"] + (["scan --alert --offline"] if args.with_scan else [])
    if os.name == "nt":
        script = project.path("velora-tache.cmd")
        lines = ["@echo off", f'set "PYTHONPATH={pkg_parent};%PYTHONPATH%"']
        lines += [f'"{sys.executable}" -m velora -C "{project.root}" {s}' for s in steps]
        project.ensure_state()
        script.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
        task = f"Velora\\{project.name}"
        # Forme documentée par Microsoft pour un chemin avec espaces : /TR "\"C:\a b\x.cmd\""
        action = f'"{script}"' if " " in str(script) else str(script)
        cmd = ["schtasks", "/Create", "/F", "/TN", task, "/TR", action]
        cmd += ["/SC", "HOURLY"] if args.every == "hourly" else ["/SC", "DAILY", "/ST", args.time]
        print("Commande Planificateur de tâches :\n  " + subprocess.list2cmdline(cmd))
        if args.apply:
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise VeloraError(f"schtasks a échoué : {(proc.stderr or proc.stdout).strip()}")
            t.ok(f"Tâche planifiée « {task} » créée ({args.every}).")
        else:
            t.info("Ajoutez --apply pour créer la tâche.")
    else:
        hour, minute = args.time.split(":")
        when = f"0 * * * *" if args.every == "hourly" else f"{int(minute)} {int(hour)} * * *"
        joined = " && ".join(f'PYTHONPATH="{pkg_parent}" "{sys.executable}" -m velora -C "{project.root}" {s}'
                             for s in steps)
        print(f"Ajoutez cette ligne avec « crontab -e » :\n  {when} {joined}")
    return 0


# --------------------------------------------------------------------------- proof

def cmd_proof(args) -> int:
    from velora import proof
    project = _project(args)
    if args.action == "create":
        t.title(f"Preuve d'antériorité · {project.name}")
        meta = proof.create_proof(project, note=args.note or "", archive=args.archive,
                                  network=not args.offline, log=lambda m: t.info(m))
        t.ok(f"Preuve {meta['id']} créée — empreinte {meta['sha256']}")
        print(t.c(f"  Dossier : {project.path('proofs', meta['id'])}  (voir CERTIFICAT.txt)", "grey"))
        if not meta["timestamps"]:
            t.warn("Aucun horodatage tiers obtenu : la preuve n'a que la date de votre ordinateur.")
        if not args.archive:
            t.info("Conseil : --archive conserve une copie exacte des sources avec la preuve.")
        return 0
    if args.action == "list":
        proofs = proof.list_proofs(project)
        if not proofs:
            print("Aucune preuve. → velora proof create")
        for p in proofs:
            stamps = ", ".join(s.get("authority", "opentimestamps") for s in p["timestamps"]) or "hors-ligne"
            print(f"  {p['id']}  {p['files']} fichiers  {t.c(p['sha256'][:16] + '…', 'grey')}  [{stamps}]"
                  + (f"  « {p['note']} »" if p.get("note") else ""))
        return 0
    report = proof.verify_proof(project, args.id)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    t.title(f"Vérification de la preuve {report['id']}")
    (t.ok if report["manifest_intact"] else t.err)(
        "Manifeste intact" if report["manifest_intact"] else "Manifeste MODIFIÉ depuis sa création !")
    for ts in report["timestamps"]:
        if "note" in ts:
            t.info(f"{ts['file']} : {ts['note']}")
        elif ts.get("error"):
            t.err(f"{ts['file']} : {ts['error']}")
        else:
            msg = f"{ts['file']} : horodaté le {ts['time']}"
            if ts.get("openssl"):
                msg += f" — signature OpenSSL : {ts['openssl']}"
            (t.ok if ts["digest_match"] else t.err)(msg + ("" if ts["digest_match"] else " — EMPREINTE DIFFÉRENTE"))
    if report["archive"]:
        (t.ok if report["archive"]["ok"] else t.err)(
            "Copie des sources (sources.zip) conforme" if report["archive"]["ok"]
            else f"sources.zip non conforme : {len(report['archive']['problems'])} fichier(s)")
    changed = len(report["modified"]) + len(report["missing"]) + len(report["added"])
    if changed:
        t.info(f"Le projet a évolué depuis : {len(report['modified'])} modifié(s), {len(report['missing'])} "
               f"supprimé(s), {len(report['added'])} ajouté(s) (normal — la preuve couvre l'état à sa date).")
        for rel in report["modified"][:10]:
            print(t.c(f"    ~ {rel}", "grey"))
    else:
        t.ok("Les fichiers actuels sont identiques à ceux horodatés.")
    ok = report["manifest_intact"] and all(ts.get("digest_match", True) for ts in report["timestamps"])
    return 0 if ok else 1


# --------------------------------------------------------------------------- protect

def cmd_protect(args) -> int:
    project = _project(args)
    if args.action == "license":
        from velora.protect import license
        author = args.author or project.config.get("author")
        path = license.write_license(project, args.type, author, args.contact or "", overwrite=args.force)
        t.ok(f"{path.name} ({args.type}) écrit pour {author}")
        return 0
    if args.action == "headers":
        from velora.protect import license
        author = args.author or project.config.get("author")
        changed = license.apply_headers(project, author, args.type, dry_run=args.dry_run)
        verb = "recevraient" if args.dry_run else "ont reçu"
        t.ok(f"{len(changed)} fichier(s) {verb} un en-tête de copyright")
        for rel in changed[:30]:
            print(t.c(f"  + {rel}", "grey"))
        if len(changed) > 30:
            print(t.c(f"  … et {len(changed) - 30} autres", "grey"))
        return 0
    if args.action == "fingerprint":
        from velora.protect import fingerprint
        info = fingerprint.save_db(project)
        t.ok(f"Empreintes enregistrées : {info['files']} fichiers de code, {info['fingerprints']} empreintes")
        t.info("Horodatez-les pour pouvoir prouver leur date : velora proof create")
        return 0
    if args.action == "compare":
        from velora.protect import fingerprint
        if not args.suspect:
            raise VeloraError("Précisez le code suspect : velora protect compare <dossier ou fichier>")
        res = fingerprint.compare(project, Path(args.suspect), threshold=args.threshold, use_db=not args.current)
        if args.json:
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0
        t.title(f"Comparaison avec {args.suspect}")
        print(t.c(f"  Référence : {res['reference']} ({res['reference_files']} fichiers) — suspect : "
                  f"{res['suspect_files']} fichiers", "grey"))
        s, f = res["suspect_similarity"], res["reference_coverage"]
        print(f"  Part du code suspect issue de votre projet : {s['strict']:.0%} (strict) · {s['fuzzy']:.0%} (flou)")
        print(f"  Part de votre projet retrouvée chez le suspect : {f['strict']:.0%} (strict) · {f['fuzzy']:.0%} (flou)")
        for m in res["matches"][:20]:
            src = ", ".join(m.get("sources", []))
            print(f"  {max(m['strict'], m['fuzzy']):>4.0%}  {m['file']}  {t.c('← ' + src, 'grey')}")
        top = max(s["strict"], s["fuzzy"] * 0.8)
        verdict = ("Copie très probable" if top >= 0.5 else "Reprise partielle probable" if top >= 0.2
                   else "Pas de similarité significative")
        print(f"\n  Verdict : {t.c(verdict, 'bold')}")
        if top >= 0.2:
            t.info("Conservez ce rapport (--json), vos preuves horodatées, et consultez un avocat en propriété "
                   "intellectuelle avant toute démarche.")
        return 0
    if args.action == "audit":
        from velora.protect import exposure
        findings, recs = exposure.audit(project.root)
        t.title(f"Exposition du code client · {project.name}")
        if findings:
            _print_findings(findings)
        else:
            t.ok("Rien d'alarmant dans les fichiers publiés.")
        t.title("Recommandations")
        for r in recs:
            print(f"  • {r}")
        return 1 if any(at_least(f.severity, "high") for f in findings) else 0
    return 0


def cmd_ui(args) -> int:
    from velora.ui.server import serve
    serve(port=args.port, open_browser=not args.no_browser, initial=args.project)
    return 0


# --------------------------------------------------------------------------- parseur

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="velora", description="Velora Protect — sécurité, sauvegarde, preuve "
                                "d'antériorité et protection du code.")
    p.add_argument("-C", "--project", help="dossier du projet (par défaut : dossier courant)")
    p.add_argument("--version", action="version", version=f"velora {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="<commande>")

    s = sub.add_parser("init", help="initialiser Velora dans un projet")
    s.add_argument("--name")
    s.add_argument("--author")
    s.add_argument("--backup-dest", action="append", help="destination de sauvegarde (répétable)")
    s.add_argument("--webhook", help="URL de webhook pour les alertes")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("config", help="lire/modifier la configuration")
    s.add_argument("action", choices=["show", "get", "set", "add", "remove"])
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?")
    s.set_defaults(func=cmd_config)

    s = sub.add_parser("status", help="état du projet")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("scan", help="analyse de sécurité (secrets, dépendances, configuration)")
    s.add_argument("--offline", action="store_true", help="ne pas interroger OSV.dev")
    s.add_argument("--staged", action="store_true", help="fichiers indexés uniquement (hook pre-commit)")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"])
    s.add_argument("--json", action="store_true")
    s.add_argument("--all", action="store_true", help="afficher tous les constats")
    s.add_argument("--alert", action="store_true", help="envoyer une alerte webhook si problème bloquant")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("web", help="tester la sécurité d'un site en ligne (HTTPS, en-têtes, fichiers exposés…)")
    s.add_argument("url", help="adresse du site, ex. https://exemple.fr")
    s.add_argument("--allow-private", action="store_true", help="autoriser localhost / réseau local (site en développement)")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"])
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_web)

    from velora.scan.hardening import PLATFORMS
    s = sub.add_parser("harden", help="configuration de sécurité à copier (en-têtes HTTP) pour votre hébergement")
    s.add_argument("--platform", action="append", choices=sorted(PLATFORMS),
                   help="plateforme (répétable) ; par défaut : déduite du code du projet")
    s.set_defaults(func=cmd_harden)

    s = sub.add_parser("hook", help="hook git pre-commit anti-secrets")
    s.add_argument("action", choices=["install", "uninstall"])
    s.set_defaults(func=cmd_hook)

    s = sub.add_parser("backup", help="sauvegardes")
    s.add_argument("action", choices=["run", "list", "verify", "restore", "check"])
    s.add_argument("archive", nargs="?", help="chemin, nom d'archive ou « latest »")
    s.add_argument("target", nargs="?", help="dossier de restauration")
    s.add_argument("--force", action="store_true", help="sauvegarder même sans changement")
    s.set_defaults(func=cmd_backup)

    s = sub.add_parser("schedule", help="planifier les sauvegardes automatiques")
    s.add_argument("--every", choices=["daily", "hourly"], default="daily")
    s.add_argument("--time", default="02:00", help="heure (HH:MM) pour --every daily")
    s.add_argument("--with-scan", action="store_true", help="lancer aussi un scan avec alerte")
    s.add_argument("--apply", action="store_true", help="créer réellement la tâche (Windows)")
    s.set_defaults(func=cmd_schedule)

    s = sub.add_parser("proof", help="preuves d'antériorité (empreinte + horodatage)")
    s.add_argument("action", choices=["create", "list", "verify"])
    s.add_argument("id", nargs="?", help="identifiant de la preuve à vérifier (par défaut : la dernière)")
    s.add_argument("--note", help="description (version, contexte…)")
    s.add_argument("--archive", action="store_true", help="conserver une copie exacte des sources")
    s.add_argument("--offline", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_proof)

    s = sub.add_parser("protect", help="protection contre la copie")
    s.add_argument("action", choices=["license", "headers", "fingerprint", "compare", "audit"])
    s.add_argument("suspect", nargs="?", help="(compare) dossier ou fichier suspect")
    s.add_argument("--type", choices=["proprietary", "mit"], default="proprietary")
    s.add_argument("--author")
    s.add_argument("--contact", help="(license) e-mail ou site pour les demandes d'autorisation")
    s.add_argument("--force", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--threshold", type=float, default=0.15)
    s.add_argument("--current", action="store_true", help="(compare) comparer au code actuel plutôt qu'à la base")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_protect)

    s = sub.add_parser("ui", help="tableau de bord web local")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(func=cmd_ui)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except VeloraError as e:
        t.err(str(e))
        return 2
    except KeyboardInterrupt:
        t.err("Interrompu.")
        return 130
