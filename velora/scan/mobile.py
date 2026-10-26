"""Sécurité des applications mobiles : Android, iOS, Flutter, React Native / Expo.

Manifeste et configuration réseau Android, build Gradle, Info.plist iOS, et code applicatif
(WebView, validation des certificats, stockage des jetons, trafic en clair).
"""

from __future__ import annotations

import re

from velora.scan.models import Finding

MOBILE_CODE = (".java", ".kt", ".dart", ".swift", ".m", ".mm")
RN_CODE = (".js", ".jsx", ".ts", ".tsx")

_FIX_SECURE_STORAGE = ("Stockez jetons et mots de passe dans le stockage sécurisé du système : Keychain (iOS), "
                       "EncryptedSharedPreferences / Keystore (Android), flutter_secure_storage, expo-secure-store, "
                       "react-native-keychain.")
_FIX_TRUST = ("Ne contournez jamais la validation des certificats : un attaquant sur le même Wi-Fi lirait et modifierait "
              "tout le trafic. Pour un certificat interne, utilisez le certificate pinning ou network_security_config.")

# (id, titre, sévérité, extensions, regex, conseil)
CODE_RULES = [
    ("trust-all-certificates", "Validation des certificats TLS désactivée", "critical", (".java", ".kt"),
     r"checkServerTrusted\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|"
     r"HostnameVerifier\s*\{[^}]*return\s+true|hostnameVerifier\s*\{\s*_?\w*\s*,\s*_?\w*\s*->\s*true\s*\}|"
     r"onReceivedSslError\([^)]*\)\s*\{[^}]*\.proceed\(\)", _FIX_TRUST),
    ("trust-all-certificates", "Validation des certificats TLS désactivée", "critical", (".dart",),
     r"badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true", _FIX_TRUST),
    ("trust-all-certificates", "Validation des certificats TLS désactivée", "critical", (".swift", ".m", ".mm"),
     r"\.useCredential\s*,\s*URLCredential\(trust:|allowsAnyHTTPSCertificateForHost|setAllowsAnyHTTPSCertificate",
     _FIX_TRUST),
    ("webview-js-bridge", "Pont JavaScript exposé dans une WebView", "medium", (".java", ".kt"),
     r"addJavascriptInterface\(",
     "Ne chargez que du contenu de confiance dans cette WebView (jamais d'URL externe) et annotez avec "
     "@JavascriptInterface uniquement les méthodes nécessaires."),
    ("webview-file-access", "WebView avec accès aux fichiers locaux", "medium", (".java", ".kt"),
     r"setAllow(?:File|UniversalAccessFromFileURLs|FileAccessFromFileURLs)\w*\(\s*true|allow(?:File|Universal)\w*\s*=\s*true",
     "Désactivez l'accès aux fichiers (setAllowFileAccess(false)) : une page malveillante pourrait lire les données de l'app."),
    ("world-readable", "Fichier lisible par toutes les applications", "high", (".java", ".kt"),
     r"MODE_WORLD_(?:READABLE|WRITEABLE)", "Utilisez MODE_PRIVATE."),
    ("insecure-storage", "Jeton ou mot de passe en stockage non chiffré", "medium", RN_CODE,
     r"AsyncStorage\.setItem\(\s*[\"'`][^\"'`]*(?:token|jwt|password|secret|session|auth)", _FIX_SECURE_STORAGE),
    ("insecure-storage", "Jeton ou mot de passe en stockage non chiffré", "medium", (".dart",),
     r"\.set(?:String|StringList)\(\s*[\"'][^\"']*(?:token|jwt|password|secret|session)", _FIX_SECURE_STORAGE),
    ("insecure-storage", "Jeton ou mot de passe en stockage non chiffré", "medium", (".java", ".kt"),
     r"\.putString\(\s*\"[^\"]*(?:token|jwt|password|secret|session)", _FIX_SECURE_STORAGE),
    ("insecure-storage", "Jeton ou mot de passe en stockage non chiffré", "medium", (".swift", ".m"),
     r"UserDefaults[^\n]*\.set\([^\n]*forKey:\s*\"[^\"]*(?:token|jwt|password|secret|session)", _FIX_SECURE_STORAGE),
    ("sensitive-log", "Donnée sensible écrite dans les journaux", "low", (".java", ".kt", ".dart", ".swift"),
     r"(?:Log\.[dviwe]|debugPrint|NSLog|print)\([^)\n]*(?:password|token|secret)",
     "Les journaux sont lisibles (adb logcat, rapports de plantage) : n'y écrivez jamais de secret."),
    ("cleartext-url", "Adresse en HTTP non chiffré dans le code", "low", MOBILE_CODE,
     r"[\"']http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0|schemas\.android\.com|www\.w3\.org|ns\.adobe\.com|"
     r"xmlpull\.org|apache\.org|xml\.org|purl\.org)[\w.-]+",
     "Utilisez https:// : en HTTP, tout le trafic (identifiants compris) peut être lu ou modifié en route."),
]

_COMPILED = [(rid, t, s, exts, re.compile(rx, re.I | re.S if rid == "trust-all-certificates" else re.I), fix)
             for rid, t, s, exts, rx, fix in CODE_RULES]

DANGEROUS_PERMISSIONS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "CAMERA", "READ_PHONE_STATE",
    "CALL_PHONE", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE", "BODY_SENSORS",
    "READ_CALENDAR", "WRITE_CALENDAR", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
}


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def check_file(rel: str, text: str) -> list[Finding]:
    lower = rel.lower()
    name = lower.rsplit("/", 1)[-1]
    findings = []
    for rid, title, sev, exts, regex, fix in _COMPILED:
        if not lower.endswith(exts):
            continue
        m = regex.search(text)
        if m:
            line = _line(text, m.start())
            if "velora:ignore" not in text.splitlines()[line - 1]:
                findings.append(Finding("mobile", rid, title, sev, rel, line, fix=fix))
    if name == "androidmanifest.xml":
        findings += _check_manifest(rel, text)
    elif lower.endswith(".xml") and "<network-security-config" in text:
        findings += _check_network_config(rel, text)
    elif name in ("build.gradle", "build.gradle.kts"):
        findings += _check_gradle(rel, text)
    elif name == "info.plist":
        findings += _check_plist(rel, text)
    elif name in ("app.json", "app.config.json") and '"expo"' in text:
        findings += _check_expo(rel, text)
    return findings


def _attr(tag: str, name: str) -> str | None:
    m = re.search(r"android:%s\s*=\s*\"([^\"]*)\"" % name, tag)
    return m.group(1) if m else None


def _check_manifest(rel: str, text: str) -> list[Finding]:
    out = []
    app = re.search(r"<application\b[^>]*>", text, re.S)
    if app:
        tag, line = app.group(0), _line(text, app.start())
        if _attr(tag, "debuggable") == "true":
            out.append(Finding("mobile", "android-debuggable", "Application Android débogable", "high", rel, line,
                               fix="Retirez android:debuggable : n'importe qui peut alors inspecter la mémoire et "
                                   "exécuter du code dans l'app (Gradle le gère pour les builds debug)."))
        if _attr(tag, "usesCleartextTraffic") == "true":
            out.append(Finding("mobile", "android-cleartext", "Trafic HTTP en clair autorisé", "high", rel, line,
                               fix="Retirez usesCleartextTraffic=\"true\" ; si un domaine précis l'exige, autorisez-le "
                                   "seul dans network_security_config.xml."))
        if _attr(tag, "allowBackup") == "true":
            out.append(Finding("mobile", "android-backup", "Sauvegarde des données de l'app autorisée", "low", rel, line,
                               fix="android:allowBackup=\"false\" (ou règles fullBackupContent / dataExtractionRules) : "
                                   "les données, jetons compris, sont extractibles via adb backup."))

    exported = []
    for m in re.finditer(r"<(activity|activity-alias|service|receiver|provider)\b([^>]*?)(/>|>(.*?)</\1>)", text, re.S):
        kind, attrs, body = m.group(1), m.group(2), m.group(4) or ""
        if _attr(attrs, "exported") != "true" or _attr(attrs, "permission"):
            continue
        if kind.startswith("activity") and "android.intent.category.LAUNCHER" in body:
            continue
        exported.append(f"{kind} {_attr(attrs, 'name') or '?'}")
    if exported:
        out.append(Finding("mobile", "android-exported", f"{len(exported)} composant(s) exporté(s) sans permission",
                           "medium", rel, detail=", ".join(exported[:6]) + ("…" if len(exported) > 6 else ""),
                           fix="Toute app installée peut les appeler : android:exported=\"false\" si ce n'est pas voulu, "
                               "sinon protégez-les par android:permission et validez les données reçues."))

    perms = sorted({m.group(1) for m in re.finditer(r"android\.permission\.([A-Z_]+)", text)} & DANGEROUS_PERMISSIONS)
    if perms:
        out.append(Finding("mobile", "android-permissions", f"{len(perms)} permission(s) sensible(s) demandée(s)", "info",
                           rel, detail=", ".join(perms),
                           fix="Vérifiez que chacune est indispensable : Google Play et les utilisateurs les examinent, "
                               "et chaque permission élargit les dégâts possibles si l'app est compromise."))
    return out


def _check_network_config(rel: str, text: str) -> list[Finding]:
    out = []
    prod = re.sub(r"<debug-overrides>.*?</debug-overrides>", "", text, flags=re.S)
    m = re.search(r"cleartextTrafficPermitted\s*=\s*\"true\"", prod)
    if m:
        out.append(Finding("mobile", "android-cleartext", "Trafic HTTP en clair autorisé (network_security_config)",
                           "high", rel, _line(prod, m.start()),
                           fix="Limitez cleartextTrafficPermitted à des domaines précis, idéalement aucun."))
    m = re.search(r"<certificates\s+src\s*=\s*\"user\"", prod)
    if m:
        out.append(Finding("mobile", "android-user-ca", "Certificats installés par l'utilisateur acceptés", "medium",
                           rel, _line(prod, m.start()),
                           fix="Réservez <certificates src=\"user\"/> à <debug-overrides> : en production, cela facilite "
                               "l'interception du trafic."))
    return out


def _check_gradle(rel: str, text: str) -> list[Finding]:
    out = []
    release = re.search(r"release\s*\{(?:[^{}]|\{[^{}]*\})*\}", text, re.S)
    if release:
        block, start = release.group(0), release.start()
        m = re.search(r"(?:minifyEnabled|isMinifyEnabled)\s*=?\s*false", block)
        if m:
            out.append(Finding("mobile", "android-no-minify", "Build release sans minification ni obfuscation (R8)",
                               "medium", rel, _line(text, start + m.start()),
                               fix="minifyEnabled true (isMinifyEnabled = true en Kotlin DSL) et shrinkResources : "
                                   "le code décompilé devient bien plus difficile à copier."))
        m = re.search(r"(?:debuggable|isDebuggable)\s*=?\s*true", block)
        if m:
            out.append(Finding("mobile", "android-debuggable", "Build release débogable", "high", rel,
                               _line(text, start + m.start()), fix="Retirez debuggable true du bloc release."))
    m = re.search(r"(?:storePassword|keyPassword)\s*=?\s*[\"'](?!\$)[^\"']{3,}[\"']", text)
    if m:
        out.append(Finding("mobile", "keystore-password", "Mot de passe du keystore écrit dans build.gradle", "high",
                           rel, _line(text, m.start()),
                           fix="Lisez-le depuis keystore.properties (non commité) ou une variable d'environnement : "
                               "avec le keystore, n'importe qui peut publier une fausse mise à jour de votre app."))
    return out


def _check_plist(rel: str, text: str) -> list[Finding]:
    out = []
    checks = [
        ("NSAllowsArbitraryLoads", "ios-ats-disabled", "App Transport Security désactivé (HTTP autorisé partout)", "high"),
        ("NSAllowsArbitraryLoadsInWebContent", "ios-ats-web", "HTTP autorisé dans les WebViews", "medium"),
        ("NSExceptionAllowsInsecureHTTPLoads", "ios-ats-exception", "Exception ATS : HTTP autorisé pour un domaine", "low"),
    ]
    for key, rid, title, sev in checks:
        m = re.search(r"<key>%s</key>\s*<true\s*/>" % key, text)
        if m:
            out.append(Finding("mobile", rid, title, sev, rel, _line(text, m.start()),
                               fix="Passez vos serveurs en HTTPS et retirez cette exception (Apple demande une "
                                   "justification lors de la revue)."))
    return out


def _check_expo(rel: str, text: str) -> list[Finding]:
    m = re.search(r"\"usesCleartextTraffic\"\s*:\s*true", text)
    if not m:
        return []
    return [Finding("mobile", "android-cleartext", "Trafic HTTP en clair autorisé (Expo)", "high", rel,
                    _line(text, m.start()), fix="Retirez usesCleartextTraffic et utilisez HTTPS.")]


def check_project(all_files: list[str], stack: list[str]) -> list[Finding]:
    findings = []
    if "Android" in stack and not any(f.endswith(("proguard-rules.pro", "proguard-android.txt")) for f in all_files) \
            and "Flutter" not in stack and "React Native" not in stack:
        findings.append(Finding("mobile", "android-no-proguard", "Aucune règle R8/ProGuard dans le projet", "low",
                                fix="Ajoutez proguard-rules.pro et activez minifyEnabled pour le build release."))
    if "Flutter" in stack:
        findings.append(Finding("mobile", "flutter-obfuscate", "Rappel : compilez Flutter avec obfuscation", "info",
                                fix="flutter build apk|ipa --obfuscate --split-debug-info=build/symbols"))
    return findings
