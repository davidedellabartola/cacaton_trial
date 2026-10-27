"""Governance del progetto: chi mantiene il software, con quali regole, e se si puo' uscirne.

Idee riprese da sovereignty_check.py (segnali dai file del repository, storico git,
publiccode.yml, OpenSSF Scorecard, badge OpenSSF Best Practices, strategia di uscita),
con alcune correzioni:
- publiccode.yml: chiavi obbligatorie dello standard ATTUALE (publiccodeYmlVersion,
  platforms, categories, softwareType, legal, maintenance, ...), non quelle della v0.1
- Scorecard: percorso API corretto /projects/github.com/<owner>/<repo>
- concentrazione dei commit calcolata anche sui repository con molta storia

Ogni segnale e' Vero / Falso / Non applicabile: il punteggio e' la quota di segnali
soddisfatti tra quelli applicabili, cosi' un repository non viene penalizzato per
qualcosa che non lo riguarda (es. lockfile in un progetto senza dipendenze) o che non
si puo' sapere (es. proprieta' dell'organizzazione senza rete).
"""

import json
import os
import re
import urllib.parse
import urllib.request

from ..sbom import inspect_text
from ..target import days_since
from .licenses import is_osi

PUBLICCODE_REQUIRED = ("publiccodeYmlVersion", "name", "url", "platforms", "categories",
                       "developmentStatus", "softwareType", "description", "legal", "maintenance",
                       "localisation")
MANIFESTS = {"package.json", "go.mod", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle",
             "build.gradle.kts", "Cargo.toml", "composer.json", "Gemfile", "Pipfile", "vcpkg.json",
             "conanfile.txt", "packages.config"}
LOCKS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "poetry.lock", "uv.lock", "Cargo.lock",
         "composer.lock", "Gemfile.lock", "Pipfile.lock", "gradle.lockfile", "packages.lock.json", "conan.lock"}
SBOM_FILE_RE = re.compile(r"(^|/)(sbom|bom)[^/]*\.(json|xml)$|\.(cdx|spdx)\.(json|xml)$|\.spdx(\.rdf|\.tv)?$|"
                          r"\.(cdx|bom)\.xml$|\.spdx\.rdf\.xml$", re.I)
LICENSE_TEXTS = [("AGPL-3.0", "gnu affero general public license"), ("LGPL-3.0", "gnu lesser general public license"),
                 ("GPL-3.0", "gnu general public license"), ("Apache-2.0", "apache license"),
                 ("MPL-2.0", "mozilla public license"), ("EUPL-1.2", "european union public licen"),
                 ("MIT", "permission is hereby granted, free of charge"),
                 ("BSD-3-Clause", "redistribution and use in source and binary forms"),
                 ("ISC", "permission to use, copy, modify, and/or distribute"),
                 ("Unlicense", "free and unencumbered software"), ("MIT", "mit license"),
                 ("BSL-1.0", "boost software license"), ("EPL-2.0", "eclipse public license - v 2.0"),
                 ("EPL-2.0", "eclipse public license 2.0"), ("EPL-1.0", "eclipse public license")]
# parole che nella documentazione indicano come portare via i dati (criterio di non-lock-in)
EXPORT_HINTS = ("esportazione", "esportare", "esporta ", "data export", "export data", "import/export",
                "migrat", "interoperab", "open standard", "standard aperti", "formati standard",
                "standard format", "backup", "ripristino", "restore", "migrazione")
SCORECARD_API = "https://api.scorecard.dev/projects/github.com/"
GITHUB_API = "https://api.github.com/repos/"
BESTPRACTICES_API = "https://www.bestpractices.dev/projects.json?url="
MAX_FILES = 200_000


def _list(root):
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", ".venv", "vendor")]
        out += [os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/") for f in fn]
        if len(out) > MAX_FILES:
            break
    return out


def _read(root, rel, limit=200_000):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def license_from_text(low: str) -> str:
    for spdx, phrase in LICENSE_TEXTS:
        if phrase in low:
            if spdx.startswith(("GPL", "LGPL")) and "version 2" in low[:800] and "version 3" not in low[:800]:
                return spdx.replace("3.0", "2.0")
            if spdx == "LGPL-3.0" and "version 2.1" in low[:800]:
                return "LGPL-2.1"
            return spdx
    return ""


def detect_license(root, top_files) -> tuple:
    """(licenza, da dove e' stata letta). Prima il file di licenza, poi i manifest del progetto."""
    lic_files = [f for f in sorted(top_files) if re.match(r"(licen[cs]e|copying)", f, re.I)]
    for f in lic_files:
        spdx = license_from_text(_read(root, f, 8000).lower())
        if spdx:
            return spdx, f
    try:
        lic = json.loads(_read(root, "package.json") or "{}").get("license")
        if isinstance(lic, dict):
            lic = lic.get("type")
        if isinstance(lic, str) and lic:
            return lic, "package.json"
    except ValueError:
        pass
    m = re.search(r'(?m)^\s*license\s*=\s*"([^"]+)"', _read(root, "Cargo.toml", 8000))
    if m:
        return m.group(1), "Cargo.toml"
    try:
        import tomllib
        with open(os.path.join(root, "pyproject.toml"), "rb") as fh:
            pj = tomllib.load(fh)
        lic = (pj.get("project") or {}).get("license") or ((pj.get("tool") or {}).get("poetry") or {}).get("license")
        if isinstance(lic, dict):
            lic = lic.get("text") or lic.get("type") or lic.get("file")
        if isinstance(lic, str) and lic:
            return lic, "pyproject.toml"
    except Exception:
        pass
    return ("presente, tipo non riconosciuto", lic_files[0]) if lic_files else ("", "")


def license_extra_terms(root, lic_file) -> str:
    """Termini aggiunti PRIMA del testo standard della licenza (es. AGPL "supplemented" secondo la sez. 7,
    Commons Clause): restringono o condizionano il riuso, quindi l'identificativo da solo non basta."""
    if not re.match(r"(licen[cs]e|copying)", lic_file.rsplit("/", 1)[-1], re.I):
        return ""
    low = _read(root, lic_file, 20_000).lower()
    # inizio del testo standard: riga del copyright della FSF, intestazione Apache, MPL, EUPL
    m = re.search(r"copyright \S* ?2007 free software foundation|free software foundation, inc\.|"
                  r"apache license\s+version 2\.0|mozilla public license,? version 2|european union public licen[cs]e v",
                  low)
    prefix = low[:m.start()] if m else ""
    if len(prefix) < 150 or not re.search(r"supplement|additional terms|commons clause|additional restriction"
                                          r"|further restriction|sec(?:tion|\.)\s*7", prefix):
        return ""
    kinds = []
    if "commons clause" in prefix:
        kinds.append("Commons Clause (vietata la vendita)")
    if re.search(r"trademark|marchio|name of|his name|its name|under the name", prefix):
        kinds.append("nome e marchi non modificabili")
    if re.search(r"logo|attribution|legal notices", prefix):
        kinds.append("attribuzione obbligatoria con logo")
    return ", ".join(kinds) or "presenti prima del testo della licenza"


SOURCE_EXT = (".js", ".ts", ".jsx", ".tsx", ".java", ".py", ".c", ".h", ".cpp", ".hpp", ".cc", ".go", ".php",
              ".rb", ".cs", ".rs", ".kt", ".scala", ".swift", ".m", ".pl", ".sh")


def header_licenses(root, files) -> dict:
    """Licenze dichiarate nelle intestazioni dei sorgenti del progetto (escluso il codice di terzi copiato)."""
    from ..builtin_sbom import JS_BANNER_RE, vendored_dirs
    vendored = tuple(d + "/" for d in vendored_dirs(files))
    found = {}
    for p in [p for p in files if p.lower().endswith(SOURCE_EXT)][:3000]:
        if p.startswith(vendored) or re.search(r"[.-]min\.js$", p):
            continue
        head = _read(root, p, 2500)
        if JS_BANNER_RE.match(head):                      # libreria nota con la sua intestazione
            continue
        m = re.search(r"SPDX-License-Identifier:\s*([\w.\-+]+(?:\s+(?:OR|AND|WITH)\s+[\w.\-+]+)*)", head)
        low = head.lower()
        if m:
            lic = m.group(1)
        elif "zimbra public license" in low:
            v = re.search(r"zimbra public license,?[\s*]*version\s*([\d.]+)", low)
            lic = f"Zimbra-{v.group(1)}" if v else "Zimbra Public License"
        elif re.search(r"licen[cs]e|copyright", low):
            lic = license_from_text(low)
        else:
            lic = ""
        if lic:
            found.setdefault(lic, []).append(p)
    return found


def same_license_family(a: str, b: str) -> bool:
    """GPL-2.0-or-later dentro un progetto GPL-3.0 non e' un conflitto; Zimbra dentro AGPL si'."""
    def fam(x):
        return re.sub(r"[-\s]?v?\d.*$", "", re.sub(r"(-only|-or-later|\+)$", "", x.strip(), flags=re.I)).upper()
    fa, fb = fam(a), fam(b)
    return fa == fb or {fa, fb} <= {"GPL", "AGPL", "LGPL"}


def check_publiccode(text):
    keys = {m.group(1) for m in re.finditer(r"(?m)^([A-Za-z][\w-]*):", text)}
    return [k for k in PUBLICCODE_REQUIRED if k not in keys]


def export_signals(root, files):
    """Segnali di esportabilita'/migrazione dei dati nei README e nella documentazione."""
    docs = sorted((p for p in files if p.rsplit("/", 1)[-1].lower().startswith("readme")), key=len)[:3]
    docs += [p for p in files if p.lower().startswith(("docs/", "doc/", "documentation/"))
             and p.lower().endswith((".md", ".rst", ".txt", ".adoc"))][:8]
    text = " ".join(_read(root, p, 40_000).lower() for p in docs)
    return [h.strip() for h in EXPORT_HINTS if h in text]


VENDOR_ITEM = r"passphrase|licen[cs]e key|license file|activation|attivazione|chiave|password|token|api key|codice"
VENDOR_ASK = r"ask|request|contact|richied|chied|contatt|provided by|fornit[ao] da|rilasciat[ao] da|obtain|ottenere"
VENDOR_WHO = r"\bus\b|\bnoi\b|vendor|fornitore|\bour\b|nostr|support|assistenza|seller|sales|commercial"


def vendor_items(root, files):
    """Frasi della documentazione in cui un elemento indispensabile (chiave, passphrase, licenza di
    attivazione) va chiesto al fornitore: senza di esso il software non funziona, quindi non si cambia fornitore."""
    docs = sorted((p for p in files if p.rsplit("/", 1)[-1].lower().startswith(("readme", "install"))), key=len)[:4]
    docs += [p for p in files if p.lower().startswith(("docs/", "doc/")) and p.lower().endswith((".md", ".txt"))][:8]
    found = []
    for p in docs:
        for sent in re.split(r"(?<=[.!?])\s+|\n{2,}", _read(root, p, 60_000)):
            low = sent.lower()
            if re.search(VENDOR_ITEM, low) and re.search(VENDOR_ASK, low) and re.search(VENDOR_WHO, low):
                found.append(f"{' '.join(sent.split())[:160]} ({p})")
    return found[:3]


def _github_repo(git_url):
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", git_url or "")
    return (m.group(1), m.group(2)) if m else None


def _get_json(url, token=False):
    req = urllib.request.Request(url, headers={"User-Agent": "sovrasbom", "Accept": "application/json"})
    if token and os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def fetch_scorecard(git_url):
    """Valutazione OpenSSF Scorecard (solo GitHub, solo online). Si riferisce al branch principale."""
    gh = _github_repo(git_url)
    if not gh:
        return None
    j = {}
    for _ in range(2):          # la prima richiesta puo' scadere mentre il servizio prepara il risultato
        try:
            j = _get_json(SCORECARD_API + f"{gh[0]}/{gh[1]}")
            break
        except Exception:
            continue
    if not isinstance(j.get("score"), (int, float)):
        return None
    checks = {c.get("name"): c.get("score") for c in j.get("checks") or []}
    return {"score": round(j["score"], 1), "date": str(j.get("date") or "")[:10], "checks": checks}


def fetch_github(git_url):
    """Proprietario (organizzazione o utente) e stato di archiviazione dall'API GitHub."""
    gh = _github_repo(git_url)
    if not gh:
        return None
    try:
        j = _get_json(GITHUB_API + f"{gh[0]}/{gh[1]}", token=True)
    except Exception:
        return None
    return {"owner_type": (j.get("owner") or {}).get("type"), "archived": bool(j.get("archived"))}


def fetch_best_practices(git_url):
    """Livello del badge OpenSSF Best Practices (ex CII): passing/silver/gold, '' se assente, None se errore."""
    gh = _github_repo(git_url)
    if not gh:
        return None
    try:
        j = _get_json(BESTPRACTICES_API + urllib.parse.quote(f"https://github.com/{gh[0]}/{gh[1]}", safe=""))
    except Exception:
        return None
    if isinstance(j, list) and j and isinstance(j[0], dict):
        level = j[0].get("badge_level") or ""
        return level if level in ("passing", "silver", "gold") else ""
    return ""


def analyze(root: str, git: dict, kind: str, online: bool) -> dict:
    files = _list(root)
    base = {p.rsplit("/", 1)[-1] for p in files}
    top = {p for p in files if "/" not in p}
    top_dirs = {p.split("/")[0].lower() for p in files if "/" in p}
    low_paths = {p.lower() for p in files}
    is_source = bool(git) or kind in ("git", "archivio") or bool(
        base & (MANIFESTS | {"README.md", "README", "LICENSE", ".gitlab-ci.yml"}))
    if not is_source:
        return {"applicable": False}

    lic, lic_from = detect_license(root, top)
    osi = is_osi(lic) if lic and not lic.startswith("presente") else False
    security = any(p in low_paths for p in ("security.md", ".github/security.md", "docs/security.md"))
    owners = bool(base & {"CODEOWNERS", "MAINTAINERS", "MAINTAINERS.md", "GOVERNANCE.md"})
    conduct = any(p.endswith("code_of_conduct.md") for p in low_paths)
    docs = bool(top_dirs & {"docs", "doc", "documentation"})
    ci = any(p.startswith(".github/workflows/") for p in files) or ".circleci/config.yml" in files or bool(
        base & {".gitlab-ci.yml", "Jenkinsfile", ".drone.yml", "azure-pipelines.yml", ".travis.yml",
                "bitbucket-pipelines.yml"})
    tests = any(re.match(r"(test|tests|spec|specs|__tests__)/", p) or re.search(r"(^|/)(test_[^/]+\.py|[^/]+_test\.(go|py)|[^/]+\.(test|spec)\.[jt]sx?)$", p)
                for p in files)
    manifests, locks = base & MANIFESTS, base & LOCKS
    pc_name = next((p for p in top if p.lower() in ("publiccode.yml", "publiccode.yaml")), "")
    pc_missing = check_publiccode(_read(root, pc_name)) if pc_name else []
    sbom_files = [p for p in files if SBOM_FILE_RE.search(p)]
    sboms = [inspect_text(_read(root, p, 60_000_000), p) for p in sbom_files[:5]]
    sbom_ok = [s for s in sboms if s["valid"]]
    best_sbom = max(sbom_ok, key=lambda s: s["completeness"]) if sbom_ok else None
    exports = export_signals(root, files)

    hist = (git or {}).get("history")
    last_commit_days = days_since((git or {}).get("commit_date", ""))
    last_tag_days = days_since((git or {}).get("last_tag_date", ""))
    git_url = (git or {}).get("url", "")
    gh = fetch_github(git_url) if online else None
    scorecard = fetch_scorecard(git_url) if online else None
    best_practices = fetch_best_practices(git_url) if online else None

    if best_sbom:
        sbom_note = (f"{best_sbom['file']}: {best_sbom['format']}, completezza {round(100 * best_sbom['completeness'])}%"
                     + ("" if best_sbom["completeness"] >= 0.8 else " (sotto l'80%)"))
    elif sboms:
        sbom_note = f"{sboms[0]['file']}: non valida ({sboms[0]['format']})"
    else:
        sbom_note = ""
    from_vendor = vendor_items(root, files)
    exit_ok = osi and len(exports) >= 2 and not from_vendor
    # perche' un dato di GitHub manca: scelta dell'utente, sorgente non GitHub o servizio non raggiungibile
    if not online:
        gh_missing = "non verificato (analisi --offline)"
    elif not _github_repo(git_url):
        gh_missing = "non verificabile: la sorgente non è un repository GitHub"
    else:
        gh_missing = "API GitHub non raggiungibile"
    extra_terms = license_extra_terms(root, lic_from) if lic_from else ""
    headers = header_licenses(root, files)
    conflicts = {l: fs for l, fs in headers.items() if not same_license_family(l, lic)} if lic else {}
    if lic:
        lic_note = f"{lic} ({lic_from})" if lic_from else lic
        if extra_terms:
            lic_note += f" + termini aggiuntivi: {extra_terms}"
    else:
        lic_note = "nessun file LICENSE"
    signals = [
        ("Licenza dichiarata", bool(lic), lic_note),
        ("Licenza approvata OSI", osi if lic else False,
         (lic + (" (i termini aggiuntivi vanno letti: possono limitare il riuso)" if extra_terms else "")) if lic else ""),
        ("Stessa licenza nelle intestazioni dei file", (not conflicts) if (lic and headers) else None,
         "; ".join(f"{l}: {len(fs)} file (es. {fs[0]})" for l, fs in conflicts.items()) if conflicts
         else ("nessuna intestazione di licenza nei sorgenti" if not headers else "")),
        ("README", any(f.lower().startswith("readme") for f in top), ""),
        ("Documentazione (cartella docs/)", docs, ""),
        ("Regole per contribuire (CONTRIBUTING)", any(p.endswith("contributing.md") for p in low_paths), ""),
        ("Codice di condotta (CODE_OF_CONDUCT)", conduct, ""),
        ("Canale per le vulnerabilità (SECURITY.md)", security, ""),
        ("Responsabili dichiarati (CODEOWNERS, MAINTAINERS)", owners, ""),
        ("Build automatica (CI)", ci, ""),
        ("Test automatici", tests, ""),
        ("Versioni delle dipendenze bloccate (lockfile)", bool(locks) if manifests else None,
         ", ".join(sorted(locks)) if locks else ("nessun file di dipendenze" if not manifests else "manca il lockfile")),
        ("publiccode.yml valido (Developers Italia)", (not pc_missing) if pc_name else False,
         ("mancano: " + ", ".join(pc_missing[:4])) if pc_missing else ("" if pc_name else "assente")),
        ("SBOM pubblicata nel repository, valida e completa",
         bool(best_sbom and best_sbom["completeness"] >= 0.8), sbom_note),
        ("Strategia di uscita: esportazione e migrazione dei dati documentate", exit_ok,
         ("segnali: " + ", ".join(exports[:4])) if exports else
         ("licenza non OSI" if not osi else "nessun riferimento nei README e in docs/")),
        ("Nessuna chiave o attivazione da chiedere al fornitore", not from_vendor,
         from_vendor[0] if from_vendor else ""),
        ("Attivo: commit negli ultimi 6 mesi", (last_commit_days <= 183) if last_commit_days is not None else None,
         f"ultimo commit {last_commit_days} giorni fa" if last_commit_days is not None
         else "storico non disponibile (usa --last-commit)"),
        ("Repository non archiviato", (not gh["archived"]) if gh else None,
         "archiviato: sola lettura" if gh and gh["archived"] else ("" if gh else gh_missing)),
        ("Di un'organizzazione, non di un singolo utente", (gh["owner_type"] == "Organization") if gh and gh.get("owner_type") else None,
         (gh or {}).get("owner_type") or gh_missing),
        ("Almeno 5 autori nello storico", (hist["authors"] >= 5) if hist else None,
         f"{hist['authors']} autori" if hist else "storico non disponibile"),
        ("Più manutentori: nessuno oltre il 60% dei commit",
         (hist["top_author_share"] <= 0.6) if hist else None,
         (f"{hist['authors']} autori, il primo firma il {round(100 * hist['top_author_share'])}% "
          f"degli ultimi {hist['commits']} commit") if hist else "storico non disponibile"),
        ("OpenSSF Scorecard almeno 5/10", (scorecard["score"] >= 5) if scorecard else None,
         f"{scorecard['score']}/10 del {scorecard['date']}" if scorecard else
         (gh_missing if not online or not _github_repo(git_url) else "non disponibile")),
    ]
    applicable = [s for s in signals if s[1] is not None]
    score = round(100 * sum(1 for s in applicable if s[1]) / len(applicable)) if applicable else -1
    return {
        "applicable": True,
        "license": lic if lic and not lic.startswith("presente") else "",
        "license_from": lic_from,
        "license_osi": osi,
        "license_extra_terms": extra_terms,
        "license_conflicts": conflicts,
        "signals": [{"label": l, "ok": ok, "note": note} for l, ok, note in signals],
        "score": score,
        "history": hist,
        "last_commit_days": last_commit_days,
        "last_tag": (git or {}).get("last_tag", ""),
        "last_tag_days": last_tag_days,
        "publiccode": bool(pc_name),
        "publiccode_missing": pc_missing,
        "published_sboms": sboms,
        "exit": {"osi": osi, "signals": exports, "docs": docs, "publiccode": bool(pc_name), "ok": exit_ok,
                 "from_vendor": from_vendor},
        "github": gh,
        "scorecard": scorecard,
        "best_practices": best_practices,
    }
