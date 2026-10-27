"""Pipeline di build: come nasce il binario che la PA installa.

La SBOM dice di cosa e' fatto il software; questa analisi dice se il PROCESSO che lo
produce e' verificabile. Legge solo file (workflow CI, Dockerfile, script); in rete
consulta solo endoflife.date per sapere quali immagini di base sono fuori supporto.

Controlli:
- azioni GitHub e immagini container fissate per etichetta (tag) invece che per impronta
  (hash del commit / digest sha256): il proprietario puo' spostare un tag su altro codice
  (caso tj-actions/changed-files, 2025)
- comandi "curl | bash": eseguono codice scaricato senza verificarlo
- ADD da URL nei Dockerfile senza --checksum
- workflow GitHub: permessi del token non dichiarati (permissions:), trigger
  pull_request_target (esegue con i segreti codice proposto da estranei), iniezione di
  comandi tramite ${{ github.event... }} dentro run: (titoli e testi scritti da chiunque)
- presenza di firme, attestazioni di provenienza e SBOM tra i passi della pipeline
Le righe commentate (#) vengono ignorate.
"""

import json
import os
import re
import urllib.request
from datetime import date

OFFICIAL_OWNERS = {"actions", "github", "docker"}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PIPE_SHELL = re.compile(r"\b(curl|wget)\b[^|\n;]*\|\s*(sudo\s+(-\S+\s+)*)?(ba|z|da|k)?sh\b|"
                        r"\b(ba)?sh\s+<\(\s*(curl|wget)\b|\bsh\s+-c\s+\"?\$\(\s*(curl|wget)\b")
SIGN_RE = re.compile(r"cosign|sigstore|attest-build-provenance|slsa-github-generator|in-toto|"
                     r"gpg\s+.*--(detach-)?sign|minisign|signify", re.I)
SBOM_RE = re.compile(r"\bsyft\b|anchore/sbom-action|cyclonedx|spdx|trivy\s+.*--format\s+(cyclonedx|spdx)", re.I)
CHECKSUM_RE = re.compile(r"sha256sum|sha512sum|shasum\s+-a\s*256", re.I)
MAX_FILE = 2_000_000
# ${{ ... }} con testo scritto da chiunque (titolo di una issue, nome di un branch...): dentro run: diventa codice
INJECTION_RE = re.compile(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|"
                          r"head_commit|commits|pages|workflow_run)\b[\w.\[\]*]*|github\.head_ref)\s*\}\}")
RUN_KEY_RE = re.compile(r"^(\s*)(-\s+)?(run|script):\s*(.*)$")
# Immagini di base il cui supporto (aggiornamenti di sicurezza gratuiti) e' terminato.
# Tabella dichiarata, aggiornata a ottobre 2026: online viene sostituita dai dati di endoflife.date.
EOL_IMAGES = {
    "centos:6": "2020-11", "centos:7": "2024-06", "centos:8": "2021-12",
    "ubuntu:14.04": "2019-04", "ubuntu:16.04": "2021-04", "ubuntu:18.04": "2023-05", "ubuntu:20.04": "2025-05",
    "ubuntu:23.04": "2024-01", "ubuntu:23.10": "2024-07", "ubuntu:24.10": "2025-07", "ubuntu:25.04": "2026-01",
    "debian:8": "2020-06", "debian:9": "2022-06", "debian:10": "2024-06", "debian:11": "2026-08",
    "debian:jessie": "2020-06", "debian:stretch": "2022-06", "debian:buster": "2024-06", "debian:bullseye": "2026-08",
    "python:2": "2020-01", "python:3.6": "2021-12", "python:3.7": "2023-06", "python:3.8": "2024-10",
    "python:3.9": "2025-10",
    "node:10": "2021-04", "node:12": "2022-04", "node:14": "2023-04", "node:16": "2023-09", "node:17": "2022-06",
    "node:18": "2025-04", "node:19": "2023-06", "node:20": "2026-04", "node:21": "2024-06", "node:23": "2025-06",
    "node:25": "2026-06",
    "alpine:3.15": "2023-11", "alpine:3.16": "2024-05", "alpine:3.17": "2024-11", "alpine:3.18": "2025-05",
    "alpine:3.19": "2025-11", "alpine:3.20": "2026-04",
    "golang:1.20": "2024-02", "golang:1.21": "2024-08", "golang:1.22": "2025-02", "golang:1.23": "2025-08",
    "golang:1.24": "2026-02", "golang:1.25": "2026-08",
}
# immagine Docker -> prodotto su endoflife.date
EOL_PRODUCTS = {"python": "python", "node": "nodejs", "debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine",
                "centos": "centos", "golang": "go", "ruby": "ruby", "php": "php", "postgres": "postgresql",
                "nginx": "nginx", "redis": "redis", "mysql": "mysql", "mariadb": "mariadb"}
EOL_API = "https://endoflife.date/api/{}.json"


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read(MAX_FILE)
    except OSError:
        return ""


def _files(root):
    """Seleziona solo i file che descrivono la build (non legge tutto il repository)."""
    out = {"workflow": [], "dockerfile": [], "script": [], "ci": []}
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", ".venv", "vendor")]
        rel_dir = os.path.relpath(dp, root).replace(os.sep, "/")
        for f in fn:
            rel = f if rel_dir == "." else f"{rel_dir}/{f}"
            low = f.lower()
            if rel_dir.startswith(".github/workflows") and low.endswith((".yml", ".yaml")):
                out["workflow"].append(rel)
            elif rel_dir.startswith(".github/actions") and low in ("action.yml", "action.yaml"):
                out["workflow"].append(rel)
            elif low.startswith(("dockerfile", "containerfile")) or low.endswith(".dockerfile"):
                out["dockerfile"].append(rel)
            elif low in (".gitlab-ci.yml", "jenkinsfile", ".drone.yml", "azure-pipelines.yml",
                         "bitbucket-pipelines.yml", ".travis.yml") or rel == ".circleci/config.yml":
                out["ci"].append(rel)
            elif low.endswith((".sh", ".bash")) or low == "makefile":
                out["script"].append(rel)
    return out


def _finding(sev, kind, where, text, detail):
    return {"severity": sev, "kind": kind, "where": where, "text": text.strip()[:120], "detail": detail}


def _image_parts(img):
    """'docker.io/library/python:3.9-slim@sha256:..' -> ('python', '3.9-slim')."""
    name = img.split("@")[0]
    repo, _, tag = name.rpartition(":") if ":" in name.rsplit("/", 1)[-1] else (name, "", "latest")
    return repo.rsplit("/", 1)[-1].lower(), tag.lower()


def fetch_eol(images) -> dict:
    """Cicli di vita da endoflife.date per i prodotti delle immagini usate: {immagine: data o "sì"}."""
    out, cycles = {}, {}
    for img in images:
        repo, tag = _image_parts(img)
        product = EOL_PRODUCTS.get(repo)
        if not product:
            continue
        if product not in cycles:
            try:
                req = urllib.request.Request(EOL_API.format(product), headers={"User-Agent": "sovrasbom"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    cycles[product] = json.loads(r.read())
            except Exception:
                cycles[product] = None
        best = None
        for c in cycles[product] or []:
            names = [str(c.get("cycle", "")).lower()]
            if c.get("codename"):
                names.append(str(c["codename"]).lower().split()[0])
            for n in names:
                if n and (tag == n or tag.startswith(n + ".") or tag.startswith(n + "-")):
                    if best is None or len(n) > best[0]:
                        best = (len(n), c)
        if best:
            eol = best[1].get("eol")
            if eol is True or (isinstance(eol, str) and eol <= date.today().isoformat()):
                out[img] = eol[:7] if isinstance(eol, str) else "data non indicata"
            else:
                out[img] = ""                          # ancora supportata
    return out


def _check_workflow(rel, lines, findings):
    """Controlli specifici dei workflow GitHub Actions."""
    code = [(n, l) for n, l in enumerate(lines, 1) if not l.lstrip().startswith("#")]
    text = "\n".join(l for _, l in code)
    if not re.search(r"(?m)^\s*permissions\s*:", text):
        findings.append(_finding("Bassa", "permessi non dichiarati", rel, "permissions: assente",
                                 "il token del workflow riceve i permessi predefiniti, spesso anche in scrittura"))
    for n, l in code:
        if re.search(r"\bpull_request_target\b", l):
            checkout_pr = re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", text)
            findings.append(_finding("Alta" if checkout_pr else "Media", "pull_request_target", f"{rel}:{n}", l,
                                     "esegue con i segreti del progetto in risposta a contributi esterni"
                                     + (" e scarica il loro codice" if checkout_pr else "")))
            break
    block_indent = None
    for n, l in code:
        indent = len(l) - len(l.lstrip(" "))
        if block_indent is not None and l.strip() and indent <= block_indent:
            block_indent = None
        m = RUN_KEY_RE.match(l)
        in_run = block_indent is not None
        if m:
            rest = m.group(4).strip()
            if rest[:1] in ("|", ">"):
                block_indent = len(m.group(1)) + len(m.group(2) or "")
                continue
            in_run = True
        if in_run and INJECTION_RE.search(l):
            findings.append(_finding("Alta", "iniezione di comandi", f"{rel}:{n}", l,
                                     "testo scritto da chiunque (issue, PR, branch) inserito in un comando"))


def analyze(root: str, online: bool = False) -> dict:
    files = _files(root)
    findings, actions, images = [], [], []
    has_sign = has_sbom = has_checksum = False

    # ------------------------------------------------- workflow e CI
    for rel in files["workflow"] + files["ci"]:
        text = _read(os.path.join(root, rel))
        lines = text.splitlines()
        code = "\n".join(l for l in lines if not l.lstrip().startswith("#"))
        has_sign |= bool(SIGN_RE.search(code))
        has_sbom |= bool(SBOM_RE.search(code))
        has_checksum |= bool(CHECKSUM_RE.search(code))
        if rel.startswith(".github/workflows/"):
            _check_workflow(rel, lines, findings)
        for n, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue                                       # riga commentata: non viene eseguita
            m = re.search(r"\buses:\s*['\"]?([^'\"\s#]+)", line)
            if m:
                ref = m.group(1)
                if ref.startswith("./"):
                    continue                                   # azione locale: sta nel repository
                if ref.startswith("docker://"):
                    images.append((ref[9:], f"{rel}:{n}"))
                    continue
                name, _, version = ref.partition("@")
                owner = name.split("/")[0].lower()
                pinned = bool(SHA_RE.match(version))
                actions.append({"name": name, "version": version, "pinned": pinned,
                                "official": owner in OFFICIAL_OWNERS, "where": f"{rel}:{n}"})
                continue
            m = re.search(r"^\s*-?\s*image:\s*['\"]?([^'\"\s#]+)", line)
            if m and "${{" not in m.group(1) and "$" not in m.group(1):
                images.append((m.group(1), f"{rel}:{n}"))
            if PIPE_SHELL.search(line):
                findings.append(_finding("Alta", "curl | bash", f"{rel}:{n}", line,
                                         "esegue codice scaricato senza verificarlo"))

    # ------------------------------------------------- Dockerfile
    for rel in files["dockerfile"]:
        text = _read(os.path.join(root, rel))
        stages = set()
        for n, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith("#"):
                continue
            m = re.match(r"(?i)FROM\s+(--platform=\S+\s+)?(\S+)(\s+AS\s+(\S+))?", s)
            if m:
                img = m.group(2)
                if m.group(4):
                    stages.add(m.group(4).lower())
                if img.lower() != "scratch" and img.lower() not in stages and "$" not in img:
                    images.append((img, f"{rel}:{n}"))
            if PIPE_SHELL.search(s):
                findings.append(_finding("Alta", "curl | bash", f"{rel}:{n}", s,
                                         "esegue codice scaricato senza verificarlo, dentro l'ambiente di build"))
            if re.match(r"(?i)ADD\s+(?!.*--checksum)\S*https?://", s):
                findings.append(_finding("Media", "ADD da URL", f"{rel}:{n}", s,
                                         "scarica un file senza verificarne l'impronta"))

    # ------------------------------------------------- script di build
    for rel in files["script"][:500]:
        for n, line in enumerate(_read(os.path.join(root, rel)).splitlines(), 1):
            if not line.lstrip().startswith("#") and PIPE_SHELL.search(line):
                findings.append(_finding("Alta", "curl | bash", f"{rel}:{n}", line,
                                         "esegue codice scaricato senza verificarlo"))

    # ------------------------------------------------- riepilogo azioni e immagini
    distinct = {}
    for a in actions:
        distinct.setdefault((a["name"], a["version"]), a)
    for (name, version), a in sorted(distinct.items()):
        if not a["pinned"]:
            sev = "Media" if a["official"] else "Alta"
            who = "di GitHub/Docker" if a["official"] else "di un autore esterno"
            uses = sum(1 for x in actions if x["name"] == name and x["version"] == version)
            findings.append(_finding(sev, "azione non bloccata", a["where"], f"{name}@{version}",
                                     f"azione {who} fissata per tag, usata {uses} volte"))
    img_distinct = {}
    for img, where in images:
        img_distinct.setdefault(img, where)
    unpinned_imgs = [i for i in img_distinct if "@sha256:" not in i]
    online_eol = fetch_eol(img_distinct) if online and img_distinct else {}
    eol = []
    for img, where in sorted(img_distinct.items()):
        if img in online_eol:
            end = online_eol[img]                      # dato di endoflife.date: "" = ancora supportata
        else:
            repo, tag = _image_parts(img)
            base = f"{repo}:{tag}"
            end = next((d for name, d in EOL_IMAGES.items()
                        if base == name or base.startswith(name + "-") or base.startswith(name + ".")), "")
        if end:
            eol.append(img)
            findings.append(_finding("Alta", "base fuori supporto", where, img,
                                     f"sistema senza aggiornamenti di sicurezza dal {end}"))
    for img in sorted(unpinned_imgs):
        findings.append(_finding("Media", "immagine senza digest", img_distinct[img], img,
                                 "immagine indicata per tag, il contenuto puo' cambiare"))

    order = {"Alta": 0, "Media": 1, "Bassa": 2}
    kind_order = {"curl | bash": 0, "iniezione di comandi": 1, "pull_request_target": 2, "azione non bloccata": 3,
                  "base fuori supporto": 4, "ADD da URL": 5, "immagine senza digest": 6, "permessi non dichiarati": 7}
    findings.sort(key=lambda f: (order[f["severity"]], kind_order.get(f["kind"], 9), f["where"]))
    applicable = bool(files["workflow"] or files["ci"] or files["dockerfile"])
    third = [a for a in distinct.values() if not a["official"]]
    count = lambda kind: sum(1 for f in findings if f["kind"] == kind)
    return {
        "applicable": applicable,
        "files": {k: len(v) for k, v in files.items()},
        "actions_total": len(distinct),
        "actions_pinned": sum(1 for a in distinct.values() if a["pinned"]),
        "actions_third_party": len(third),
        "actions_third_party_unpinned": sum(1 for a in third if not a["pinned"]),
        "images_total": len(img_distinct),
        "images_unpinned": len(unpinned_imgs),
        "pipe_to_shell": count("curl | bash"),
        "images_eol": len(eol),
        "eol_source": "endoflife.date" if online_eol else "tabella interna (ottobre 2026)",
        "injections": count("iniezione di comandi"),
        "pr_target": count("pull_request_target"),
        "pr_target_high": sum(1 for f in findings if f["kind"] == "pull_request_target" and f["severity"] == "Alta"),
        "no_permissions": count("permessi non dichiarati"),
        "has_signing": has_sign,
        "has_sbom_step": has_sbom,
        "has_checksum": has_checksum,
        "findings": findings,
    }


def score(p: dict) -> int:
    """0-100: parte da 100 e toglie punti per ogni debolezza, con un tetto per categoria
    (cosi' un solo problema ripetuto molte volte non domina il risultato).
    Tetti: curl|bash 25, azioni esterne 25, iniezione di comandi 20, azioni ufficiali 10,
    immagini senza digest 10, pull_request_target 10, permessi non dichiarati 10,
    basi fuori supporto 15, nessuna firma 15. Formula dichiarata anche nel README."""
    if not p["applicable"]:
        return -1
    official_unpinned = p["actions_total"] - p["actions_pinned"] - p["actions_third_party_unpinned"]
    s = 100
    s -= 25 if p["pipe_to_shell"] else 0
    s -= min(25, 10 * p["actions_third_party_unpinned"])
    s -= 20 if p.get("injections") else 0
    s -= min(10, 3 * official_unpinned)
    s -= min(10, 2 * p["images_unpinned"])
    s -= 10 if p.get("pr_target_high") else (5 if p.get("pr_target") else 0)
    s -= min(10, 2 * p.get("no_permissions", 0))
    s -= min(15, 8 * p.get("images_eol", 0))
    s -= 15 if not p["has_signing"] else 0
    return max(0, s)
