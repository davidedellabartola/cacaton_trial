"""Generatore di SBOM integrato: legge i file di dipendenze senza strumenti esterni.

Oltre ai file di dipendenze dei sorgenti riconosce:
- pacchetti .deb (nome, versione e maintainer dal file control)
- librerie Java .jar/.war/.ear (coordinate Maven da pom.properties o dal MANIFEST),
  comprese quelle annidate in WEB-INF/lib dei .war
Non riconosce i binari compilati (es. OpenSSL): per quelli servono Syft o Trivy.

Adattato da sovereignty_check.py v3 (parser di npm/yarn/pnpm, Python, Go, Cargo,
Composer, Maven, Gradle, Ruby, NuGet, vcpkg/Conan, submodule git e cartelle vendored).
Quello che non sa leggere (es. build.gradle senza lockfile) finisce nelle note della
SBOM ("file non letti"), insieme agli indici pip alternativi e ai replace di Go,
cosi' il report lo dichiara invece di tacerlo. Si usa solo se Syft e Trivy non sono
installati: copre i repository di codice sorgente, NON i sistemi installati
(per /opt/zimbra servono Syft o Trivy, che riconoscono anche JAR e pacchetti .deb).

Perche' tenerlo: rende il tool utilizzabile con il solo Python, ad esempio da un
membro del team che non ha installato nulla.
"""

import base64
import hashlib
import io
import json
import os
import re
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

OFFICIAL = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/", "https://pypi.org/",
            "https://files.pythonhosted.org/", "https://rubygems.org/", "https://crates.io/",
            "https://index.crates.io/", "https://static.crates.io/", "https://repo.maven.apache.org/",
            "https://repo1.maven.org/", "https://proxy.golang.org/", "https://packagist.org/",
            "https://api.nuget.org/", "registry+https://github.com/rust-lang/crates.io-index",
            "sparse+https://index.crates.io/")
OFFICIAL_PYPI = ("https://pypi.org/", "https://pypi.python.org/", "https://files.pythonhosted.org/")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
# cartelle in cui di solito si copia codice di terzi dentro il repository
VENDOR_DIRS = {"vendor", "third_party", "third-party", "thirdparty", "3rdparty", "bundled", "vendors", "external"}
# cartelle che contengono anche codice del progetto: contano solo le sottocartelle con nome e versione
# (es. lib/CryptoJS v3.1.2, js/libs/jquery-3.6.0)
LIB_DIRS = {"lib", "libs", "js", "static", "assets", "plugins"}
NAME_VER_RE = re.compile(r"(.*?)[-_ ]v?([0-9]+\.[0-9][0-9A-Za-z.+_~-]*)")
# librerie JavaScript copiate spesso a mano: nome nell'intestazione o nella cartella -> pacchetto npm,
# cosi' vulnerabilita' e manutenzione si possono cercare sul registro
KNOWN_JS = {"cryptojs": "crypto-js", "crypto-js": "crypto-js", "jquery": "jquery", "jquery ui": "jquery-ui",
            "jquery-ui": "jquery-ui", "bootstrap": "bootstrap", "lodash": "lodash", "underscore": "underscore",
            "underscore.js": "underscore", "moment": "moment", "moment.js": "moment", "angularjs": "angular",
            "angular": "angular", "vue": "vue", "vue.js": "vue", "react": "react", "handlebars": "handlebars",
            "mustache": "mustache", "d3": "d3", "chart.js": "chart.js", "dompurify": "dompurify",
            "sweetalert2": "sweetalert2", "select2": "select2", "datatables": "datatables.net",
            "jszip": "jszip", "pdf.js": "pdfjs-dist", "tinymce": "tinymce", "ckeditor": "ckeditor",
            "prototype": "prototype", "backbone": "backbone", "knockout": "knockout", "forge": "node-forge",
            "jsencrypt": "jsencrypt", "sjcl": "sjcl", "highcharts": "highcharts", "leaflet": "leaflet"}
# intestazione tipica: '/*! jQuery v3.6.0 | ...' oppure '/*' e a capo 'CryptoJS v3.1.2'
JS_BANNER_RE = re.compile(r"\A\s*/\*[!*]?[\s*]*([A-Za-z][\w.\- ]{0,30}?)\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b")
KNOWN_JS_TEXT = [
    ("pajhome-md5", re.compile(r"JavaScript implementation of the RSA Data Security, Inc\. MD5[\s\S]{0,200}?"
                               r"Version ([0-9][0-9.]*)")),
    ("pajhome-sha1", re.compile(r"JavaScript implementation of the Secure Hash Algorithm, SHA-1[\s\S]{0,200}?"
                                r"Version ([0-9][0-9.]*)")),
]
ECOSYSTEM_MANIFESTS = {"package.json", "go.mod", "requirements.txt", "pyproject.toml", "pom.xml", "build.gradle",
                       "build.gradle.kts", "Cargo.toml", "composer.json", "Gemfile", "Pipfile", "vcpkg.json",
                       "conanfile.txt", "conanfile.py", "packages.config"}
MAX_FILES = 200_000


# ============================================================ utilita'
def list_files(root):
    out = []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        out += [os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/") for f in fn]
        if len(out) > MAX_FILES:
            break
    return out


def read(root, rel, limit=60_000_000):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="ignore") as f:
            return f.read(limit)
    except OSError:
        return ""


def rx(pat, s):
    m = re.search(pat, s, re.M)
    return m.group(1) if m else None


def make_purl(eco, name, version):
    n = name
    if eco == "npm" and name.startswith("@"):
        n = "%40" + name[1:]
    elif eco == "pypi":
        n = re.sub(r"[-_.]+", "-", name).lower()
    elif eco == "maven":
        n = name.replace(":", "/")
    n = urllib.parse.quote(n, safe="/%")
    return f"pkg:{eco}/{n}" + (f"@{urllib.parse.quote(version, safe='-._~')}" if version else "")


def D(name, version, eco, **kw):
    d = {"name": name, "version": version, "eco": eco, "direct": None, "dev": False,
         "resolved": None, "integrity": None, "license": None, "source_kind": "registry",
         "supplier": None, "location": None, "hashable": False}
    d.update(kw)
    d["purl"] = make_purl(eco, name, version)
    return d


def source_kind(resolved):
    r = (resolved or "").lower()
    if not r:
        return "registry"
    if r.startswith(("git+", "git:", "git@", "github:", "ssh://")) or "codeload.github.com" in r:
        return "git"
    if r.startswith(("file:", "link:", "/", "./", "../")):
        return "locale"
    return "registry" if resolved.startswith(OFFICIAL) else "altra fonte"


def to_hash(integrity):
    if not integrity:
        return None
    m = re.match(r"(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/=]+)", integrity)
    if m:
        try:
            alg = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}[m.group(1)]
            return alg, base64.b64decode(m.group(2)).hex()
        except ValueError:
            return None
    return ("SHA-256", integrity) if re.fullmatch(r"[0-9a-f]{64}", integrity) else None


# ============================================================ parser
# Ogni parser riceve (root, paths, notes) e restituisce una lista di dipendenze D(...).
# notes raccoglie cio' che il report deve dichiarare: file non letti, indici alternativi, replace.
def parse_npm(root, paths, notes):
    P, out, direct, dev = set(paths), [], set(), set()
    if "package.json" in P:
        try:
            pj = json.loads(read(root, "package.json"))
            direct = set(pj.get("dependencies", {})) | set(pj.get("optionalDependencies", {}))
            dev = set(pj.get("devDependencies", {}))
        except ValueError:
            pass
    if "package-lock.json" in P:
        try:
            j = json.loads(read(root, "package-lock.json"))
        except ValueError:
            j = {}
        for key, v in (j.get("packages") or {}).items():
            if not key or v.get("link"):
                continue
            name = v.get("name") or key.split("node_modules/")[-1]
            lic = v.get("license") if isinstance(v.get("license"), str) else None
            # diretta solo la copia al primo livello di node_modules, non quelle annidate
            out.append(D(name, v.get("version"), "npm", direct=(key == "node_modules/" + name and name in (direct | dev)),
                         dev=bool(v.get("dev")), resolved=v.get("resolved"), integrity=v.get("integrity"),
                         license=lic, source_kind=source_kind(v.get("resolved")), hashable=True))

        def walk(deps_, top=True):
            for n, v in (deps_ or {}).items():
                out.append(D(n, v.get("version"), "npm", direct=top and n in (direct | dev), dev=bool(v.get("dev")),
                             resolved=v.get("resolved"), integrity=v.get("integrity"),
                             source_kind=source_kind(v.get("resolved")), hashable=True))
                walk(v.get("dependencies"), False)
        if not j.get("packages"):
            walk(j.get("dependencies"))
    elif "yarn.lock" in P:
        for blk in re.split(r"\n\s*\n", read(root, "yarn.lock")):
            lines = [l for l in blk.splitlines() if l.strip() and not l.lstrip().startswith("#")]
            if not lines or lines[0][0] in " _" or "@patch:" in lines[0] or "@workspace:" in lines[0]:
                continue
            spec = lines[0].rstrip(":").split(",")[0].strip().strip('"')
            if "@" not in spec[1:]:
                continue
            name, body = spec[:spec.rindex("@")], "\n".join(lines[1:])
            resolved = rx(r'^\s+resolved:?\s+"?([^"\s]+)', body)
            integ = rx(r'^\s+(?:integrity|checksum):?\s+"?([^"\s]+)', body)
            out.append(D(name, rx(r'^\s+version:?\s+"?([^"\s]+)', body), "npm", direct=name in direct,
                         dev=name in dev and name not in direct, resolved=resolved,
                         integrity=integ if integ and integ.startswith("sha") else None,
                         source_kind=source_kind(resolved), hashable=resolved is not None))
    elif "pnpm-lock.yaml" in P:
        sec, last = None, None
        for ln in read(root, "pnpm-lock.yaml").splitlines():
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            ind, s = len(ln) - len(ln.lstrip(" ")), ln.strip()
            if ind == 0:
                sec, last = ("pkgs" if s in ("packages:", "snapshots:") else None), None
                continue
            if sec != "pkgs":
                continue
            if ind == 2 and s.endswith(":"):
                key = s[:-1].strip().strip("'\"")
                name, _, ver = key[1:].rpartition("/") if key.startswith("/") else key.rpartition("@")
                if name:
                    last = D(name, ver.split("(")[0] or None, "npm", direct=name in (direct | dev),
                             dev=name in dev and name not in direct)
                    out.append(last)
                else:
                    last = None
            elif ind > 2 and last is not None:
                m = re.search(r"integrity:\s*'?([^'\"\s,}]+)", s)
                if m:
                    last["integrity"] = m.group(1)
                    last["hashable"] = True
    else:
        out += [D(n, None, "npm", direct=True) for n in sorted(direct)]
        out += [D(n, None, "npm", direct=True, dev=True) for n in sorted(dev - direct)]
    return out


def parse_go(root, paths, notes):
    if "go.mod" not in paths:
        return []
    mode, reps, out = None, {}, []
    reqs = []
    for line in read(root, "go.mod").splitlines():
        s, indirect = line.split("//")[0].strip(), "// indirect" in line
        m = re.match(r"^(require|replace|exclude|retract)\s*\($", s)
        if m:
            mode = m.group(1)
            continue
        if s == ")":
            mode = None
            continue
        m = re.match(r"^(require|replace)\s+(.+)$", s)
        kind, rest = (m.group(1), m.group(2)) if m else (mode, s)
        if kind == "require" and rest:
            parts = rest.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                reqs.append((parts[0], parts[1], indirect))
        elif kind == "replace" and "=>" in rest:
            old, new = (x.split() for x in rest.split("=>", 1))
            if old and new:
                reps[old[0]] = new[0]
    for name, ver, ind in reqs:
        rep = reps.get(name)
        sk = "registry" if not rep else ("locale" if rep.startswith((".", "/")) else "altra fonte")
        if rep:
            # un replace verso un altro modulo e' spesso un fork: il codice non e' quello del progetto originale
            notes["replaces"].append(f"{name} => {rep}")
        out.append(D(name, ver, "golang", direct=not ind, source_kind=sk, resolved=rep))
    return out


def _dep_name(spec):
    m = re.match(r"([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?", spec if isinstance(spec, str) else "")
    return m.group(1) if m else None


def parse_pyproject(root, notes):
    """PEP 621 (anche optional-dependencies) e Poetry (anche dev-dependencies e gruppi).

    I vincoli (>=1.2) non sono versioni reali: le dipendenze restano senza versione.
    """
    try:
        import tomllib
    except ImportError:
        notes["unsupported"].append("pyproject.toml (serve Python 3.11+ per leggerlo)")
        return []
    try:
        with open(os.path.join(root, "pyproject.toml"), "rb") as f:
            j = tomllib.load(f)
    except (OSError, ValueError) as exc:
        notes["unsupported"].append(f"pyproject.toml (non valido: {str(exc)[:60]})")
        return []
    out = []
    proj = j.get("project") or {}
    for dep in proj.get("dependencies") or []:
        if _dep_name(dep):
            out.append(D(_dep_name(dep), None, "pypi", direct=True))
    for grp, lst in (proj.get("optional-dependencies") or {}).items():
        for dep in lst or []:
            if _dep_name(dep):
                out.append(D(_dep_name(dep), None, "pypi", direct=True,
                             dev=bool(re.search(r"dev|test|lint|doc", grp, re.I))))
    po = (j.get("tool") or {}).get("poetry") or {}
    for n in po.get("dependencies") or {}:
        if n != "python":
            out.append(D(n, None, "pypi", direct=True))
    for n in po.get("dev-dependencies") or {}:
        out.append(D(n, None, "pypi", direct=True, dev=True))
    for grp_name, grp in (po.get("group") or {}).items():
        for n in (grp or {}).get("dependencies") or {}:
            out.append(D(n, None, "pypi", direct=True, dev=grp_name != "main"))
    return out


def _parse_uv_lock(text):
    """uv.lock: [[package]] con name, version, source = { registry | git | path | editable } e hash."""
    out = []
    for blk in re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]:
        blk = re.split(r"(?m)^\[(?!\[package)", blk)[0]           # fine del blocco: prossima tabella
        name, ver = rx(r'^name = "([^"]+)"', blk), rx(r'^version = "([^"]+)"', blk)
        src = re.search(r'^source = \{\s*(\w+)\s*=\s*"([^"]*)"', blk, re.M)
        if not name or not src or src.group(1) in ("editable", "virtual"):
            continue                                              # il progetto stesso o un membro del workspace
        kind, where = src.group(1), src.group(2)
        sk = {"git": "git", "path": "locale", "directory": "locale"}.get(kind) or \
            ("registry" if where.startswith(("https://pypi.org/", "https://files.pythonhosted.org/")) else "altra fonte")
        h = rx(r'hash = "sha256:([0-9a-f]{64})"', blk)
        out.append(D(name, ver, "pypi", resolved=where if sk != "registry" else None, integrity=h,
                     source_kind=sk, hashable=sk in ("registry", "altra fonte")))
    return out


def parse_python(root, paths, notes):
    out = []
    for p in paths:
        b = p.rsplit("/", 1)[-1]
        # requirements*.txt, anche nella cartella requirements/ (es. requirements/dev.txt di pip-tools)
        if re.fullmatch(r"requirements[\w.\-]*\.txt", b) or re.match(r"(.*/)?requirements/[^/]+\.txt$", p):
            isdev = bool(re.search(r"dev|test", b))
            for line in read(root, p).splitlines():
                line = line.split(" #")[0].strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"(-i|--index-url|--extra-index-url|-f|--find-links)[\s=]+(\S+)", line)
                if m:
                    # un indice diverso da PyPI apre alla "dependency confusion": va dichiarato nel report
                    if m.group(1) == "--extra-index-url" or not m.group(2).startswith(OFFICIAL_PYPI):
                        notes["index_urls"].append(f"{p}: {line}")
                    continue
                if line.startswith(("-e", "--editable")):
                    target = re.sub(r"^(-e|--editable)[\s=]+", "", line)
                    if target in (".", "./"):
                        continue                               # il progetto stesso, installato in sviluppo
                    sk = "git" if "git+" in target else ("locale" if target.startswith((".", "/", "file:")) else "altra fonte")
                    name = rx(r"egg=([\w.\-]+)", target) or target.rstrip("/").rsplit("/", 1)[-1]
                    out.append(D(name, None, "pypi", direct=True, dev=isdev, resolved=target, source_kind=sk))
                    continue
                if line.startswith("-"):
                    continue                                   # -r, -c, --hash...: opzioni, non pacchetti
                if line.startswith(("git+", "http")) or " @ " in line:
                    url = line.split(" @ ", 1)[-1].strip()
                    name = rx(r"egg=([\w.\-]+)", line) or (line.split(" @ ")[0].strip() if " @ " in line else line)
                    out.append(D(name, None, "pypi", direct=True, dev=isdev, resolved=url,
                                 source_kind="git" if "git+" in url else source_kind(url)))
                    continue
                m = re.match(r"([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(?:==\s*([\w.\-+!]+))?", line)
                if m:
                    out.append(D(m.group(1), m.group(2), "pypi", direct=True, dev=isdev))
        elif b == "poetry.lock":
            for m in re.finditer(r'\[\[package\]\]\s+name = "([^"]+)"\s+version = "([^"]+)"', read(root, p)):
                out.append(D(m.group(1), m.group(2), "pypi"))
        elif b == "uv.lock":
            out += _parse_uv_lock(read(root, p))
        elif b == "Pipfile.lock":
            try:
                j = json.loads(read(root, p))
            except ValueError:
                continue
            for sec, isdev in (("default", False), ("develop", True)):
                for n, v in (j.get(sec) or {}).items():
                    hs = v.get("hashes") or []
                    out.append(D(n, (v.get("version") or "").lstrip("=") or None, "pypi", dev=isdev,
                                 integrity=hs[0].split(":")[-1] if hs else None, hashable=True,
                                 source_kind="git" if v.get("git") else "registry"))
    if not out and "pyproject.toml" in paths:
        out += parse_pyproject(root, notes)
    if not out and "setup.py" in paths:
        notes["unsupported"].append("setup.py (non viene eseguito: dipendenze non lette)")
    return out


def parse_cargo(root, paths, notes):
    out = []
    for p in paths:
        if p.rsplit("/", 1)[-1] != "Cargo.lock":
            continue
        for m in re.finditer(r'\[\[package\]\]\s+name = "([^"]+)"\s+version = "([^"]+)"'
                             r'(?:\s+source = "([^"]+)")?(?:\s+checksum = "([^"]+)")?', read(root, p)):
            n, v, src, ck = m.groups()
            if src:                                            # senza source: crate locale del workspace
                sk = "git" if src.startswith("git+") else "registry" if "crates.io" in src else "altra fonte"
                out.append(D(n, v, "cargo", resolved=src, integrity=ck, source_kind=sk, hashable=sk != "git"))
    return out


def parse_composer(root, paths, notes):
    if "composer.lock" not in paths:
        return []
    try:
        j = json.loads(read(root, "composer.lock"))
        cj = json.loads(read(root, "composer.json") or "{}")
    except ValueError:
        return []
    direct = set(cj.get("require", {})) | set(cj.get("require-dev", {}))
    out = []
    for sec, isdev in (("packages", False), ("packages-dev", True)):
        for v in j.get(sec, []):
            lic = v.get("license")
            out.append(D(v["name"], (v.get("version") or "").lstrip("v") or None, "composer",
                         direct=v["name"] in direct, dev=isdev,
                         license=" OR ".join(lic) if isinstance(lic, list) and lic else None))
    return out


def parse_maven(root, paths, notes):
    out, tag = [], (lambda e: e.tag.split("}")[-1])
    for p in paths:
        if p.rsplit("/", 1)[-1] != "pom.xml":
            continue
        try:
            r = ET.fromstring(read(root, p))
        except ET.ParseError:
            notes["unsupported"].append(f"{p} (XML non valido)")
            continue
        props = {tag(x): (x.text or "").strip() for pr in r if tag(pr) == "properties" for x in pr}
        val = lambda e, t: next(((c.text or "").strip() for c in e if tag(c) == t), None)
        parent = next((c for c in r if tag(c) == "parent"), None)
        own_version = val(r, "version") or (val(parent, "version") if parent is not None else None)
        if own_version:
            props.setdefault("project.version", own_version)

        def res(v):
            m = re.fullmatch(r"\$\{(.+)\}", v or "")
            return (props.get(m.group(1)) if m else v) or None
        # le versioni dichiarate una volta sola in dependencyManagement valgono per tutto il progetto
        managed = {}
        for dm in r.iter():
            if tag(dm) == "dependencyManagement":
                for dd in dm.iter():
                    if tag(dd) == "dependency":
                        managed[(val(dd, "groupId"), val(dd, "artifactId"))] = res(val(dd, "version"))
        for ch in r:
            if tag(ch) == "dependencies":
                for dd in ch:
                    g, a = val(dd, "groupId"), val(dd, "artifactId")
                    if g and a:
                        out.append(D(f"{g}:{a}", res(val(dd, "version")) or managed.get((g, a)), "maven",
                                     direct=True, dev=val(dd, "scope") == "test"))
    return out


def parse_gradle(root, paths, notes):
    out, locked_dirs = [], set()
    for p in paths:
        if p.rsplit("/", 1)[-1] != "gradle.lockfile":
            continue
        locked_dirs.add(p.rsplit("/", 1)[0] if "/" in p else "")
        for line in read(root, p).splitlines():
            line = line.split("#")[0].strip()
            if "=" not in line:
                continue
            parts = line.split("=", 1)[0].split(":")
            if len(parts) >= 3:
                out.append(D(parts[0] + ":" + parts[1], parts[2] or None, "maven", direct=True))
    for p in paths:
        b = p.rsplit("/", 1)[-1]
        d = p.rsplit("/", 1)[0] if "/" in p else ""
        if b in ("build.gradle", "build.gradle.kts") and d not in locked_dirs:
            notes["unsupported"].append(f"{p} (Gradle senza gradle.lockfile: le versioni si conoscono solo eseguendo la build)")
    return out


def parse_gem(root, paths, notes):
    if "Gemfile.lock" not in paths:
        return []
    out, kind = [], "registry"
    for line in read(root, "Gemfile.lock").splitlines():
        if line and not line.startswith(" "):
            kind = {"GIT": "git", "PATH": "locale"}.get(line.strip(), "registry")
        m = re.match(r"^\s+remote:\s+(\S+)", line)
        if m and kind == "registry" and "rubygems.org" not in m.group(1):
            kind = "altra fonte"
        m = re.match(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
        if m:
            out.append(D(m.group(1), m.group(2), "gem", source_kind=kind))
    return out


def parse_nuget(root, paths, notes):
    out = []
    for p in paths:
        b = p.rsplit("/", 1)[-1]
        if b == "packages.lock.json":
            try:
                j = json.loads(read(root, p))
            except ValueError:
                continue
            for tgt in (j.get("targets") or {}).values():
                for name, v in (tgt or {}).items():
                    v = v or {}
                    out.append(D(name, v.get("resolved"), "nuget", direct=v.get("type") == "Direct",
                                 integrity=v.get("contentHash"), hashable=v.get("type") != "Project"))
        elif b == "packages.config":
            try:
                r = ET.fromstring(read(root, p))
            except ET.ParseError:
                continue
            for el in r.iter():
                if el.tag.split("}")[-1].lower() == "package" and el.get("id"):
                    out.append(D(el.get("id"), el.get("version"), "nuget", direct=True,
                                 dev=el.get("developmentDependency") == "true"))
        elif b.endswith((".csproj", ".vbproj", ".fsproj")):
            try:
                r = ET.fromstring(read(root, p))
            except ET.ParseError:
                continue
            for el in r.iter():
                if el.tag.split("}")[-1] == "PackageReference" and el.get("Include"):
                    out.append(D(el.get("Include"), el.get("Version"), "nuget", direct=True))
    return out


def parse_vcpkg_conan(root, paths, notes):
    """Dipendenze C/C++: vcpkg.json e conanfile.txt ([requires]); conanfile.py non viene eseguito."""
    out = []
    for p in paths:
        b = p.rsplit("/", 1)[-1]
        if b == "vcpkg.json":
            try:
                j = json.loads(read(root, p))
            except ValueError:
                continue
            overrides = {o["name"]: o.get("version") or o.get("version-string")
                         for o in j.get("overrides") or [] if isinstance(o, dict) and o.get("name")}
            for v in j.get("dependencies") or []:
                if isinstance(v, dict) and v.get("name"):
                    out.append(D(v["name"], overrides.get(v["name"]) or v.get("version>="), "generic", direct=True))
                elif isinstance(v, str) and re.match(r"[\w.+-]+$", v):
                    out.append(D(v, overrides.get(v), "generic", direct=True))
        elif b == "conanfile.txt":
            sec = None
            for line in read(root, p).splitlines():
                s = line.split("#")[0].strip()
                if s.startswith("["):
                    sec = s.lower()
                    continue
                if not s or sec not in ("[requires]", "[tool_requires]", "[build_requires]") or "/" not in s:
                    continue
                n, v = s.split("/", 1)
                out.append(D(n.strip(), v.split("@")[0].strip() or None, "conan", direct=True,
                             dev=sec != "[requires]"))
        elif b == "conanfile.py":
            notes["unsupported"].append(f"{p} (ricetta Conan in Python: non viene eseguita)")
    return out


def vendored_dirs(paths):
    """Cartelle con codice di terzi copiato nel repository (vendor/, third_party/...): {percorso: nome}."""
    kids = {}
    for p in paths:
        parts = p.split("/")
        for i, seg in enumerate(parts[:-1]):
            if len(parts) <= i + 2:
                continue
            low = seg.lower()
            if low in VENDOR_DIRS or (low in LIB_DIRS and NAME_VER_RE.fullmatch(parts[i + 1])):
                kids["/".join(parts[:i + 2])] = parts[i + 1]
                break
    # con "go mod vendor" la cartella vendor/ rispecchia go.mod: non e' codice copiato a mano
    if "vendor/modules.txt" in paths:
        kids = {k: v for k, v in kids.items() if not k.startswith("vendor/")}
    return kids


# indirizzi di licenza citati nelle intestazioni delle librerie copiate
LICENSE_URLS = {"code.google.com/p/crypto-js/wiki/license": "BSD-3-Clause", "jquery.org/license": "MIT",
                "lodash.com/license": "MIT", "opensource.org/licenses/mit": "MIT", "underscorejs.org": "MIT",
                "momentjs.com": "MIT", "opensource.org/licenses/bsd-3-clause": "BSD-3-Clause",
                "apache.org/licenses/license-2.0": "Apache-2.0",
                "pajhome.org.uk": "BSD-3-Clause"}


def copy_facts(root, location):
    """Licenza dichiarata nella copia (file LICENSE o intestazione) e impronta del suo contenuto.

    L'impronta di una cartella e' lo SHA-256 dell'elenco ordinato "percorso relativo + SHA-256 del file":
    cambia se cambia anche un solo file, ed e' ricalcolabile da chiunque abbia la stessa copia.
    """
    from .analyzers.governance import license_from_text
    full = os.path.join(root, location)
    if os.path.isdir(full):
        files = sorted(os.path.relpath(os.path.join(dp, f), full).replace(os.sep, "/")
                       for dp, _, fn in os.walk(full) for f in fn)
    else:
        full, files = os.path.dirname(full), [os.path.basename(full)]
    lines, lic, author = [], None, None
    for rel in files:
        try:
            with open(os.path.join(full, rel), "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        lines.append(f"{rel}\0{hashlib.sha256(data).hexdigest()}\n")
        if re.match(r"(licen[cs]e|copying)", rel.rsplit("/", 1)[-1], re.I) or rel.endswith(".js"):
            text = data[:3000].decode("utf-8", "ignore")
            head = text.lower()
            if lic is None:
                lic = next((v for k, v in LICENSE_URLS.items() if k in head), None) or license_from_text(head) or None
            if author is None:
                # "(c) 2009-2013 by Jeff Mott. All rights reserved."  /  "Copyright 2014 OpenJS Foundation"
                m = re.search(r"(?:\(c\)|©|copyright)\s*(?:\(c\)\s*)?(?:\d{4}(?:\s*[-–,]\s*\d{4})*\s*)?(?:by\s+)?"
                              r"([A-Z][\w&'\- ]{2,50}?)\s*(?:[.,;|*<]|all rights|and other|$)", text, re.I | re.M)
                author = m.group(1).strip() if m and not re.match(r"(the|this|licen|permission)", m.group(1), re.I) \
                    else None
    digest = hashlib.sha256("".join(lines).encode()).hexdigest() if lines else None
    return lic, digest, author


def _vendored_dep(root, name, version, location):
    """Libreria copiata: se e' una libreria JavaScript nota diventa un pacchetto npm (cercabile su OSV).
    La licenza e' quella scritta nella copia, non quella del registro (le due possono differire)."""
    npm = KNOWN_JS.get(name.strip().lower())
    lic, digest, author = copy_facts(root, location)
    return D(npm or name.strip(), version, "npm" if npm else "generic", direct=True, source_kind="copiato",
             location=location, license=lic, integrity=digest, license_from="copia" if lic else None,
             supplier=author)


def parse_cc_vendored(root, paths, notes):
    """Progetti senza manifest di ecosistema (tipicamente C/C++): submodule git e librerie vendored."""
    base = {p.rsplit("/", 1)[-1] for p in paths}
    if base & ECOSYSTEM_MANIFESTS:
        return []
    out = []
    for blk in re.split(r"(?m)^\[submodule", read(root, ".gitmodules"))[1:]:
        path = rx(r"^\s*path\s*=\s*(\S+)", blk)
        url = rx(r"^\s*url\s*=\s*(\S+)", blk)
        branch = rx(r"^\s*branch\s*=\s*(\S+)", blk)
        name = path or (re.sub(r"\.git$", "", url.rstrip("/").rsplit("/", 1)[-1]) if url else None)
        if name:
            out.append(D(name, branch, "generic", direct=True, source_kind="git", resolved=url))
    for where, child in vendored_dirs(paths).items():
        m = NAME_VER_RE.fullmatch(child)
        out.append(_vendored_dep(root, m.group(1), m.group(2), where) if m else
                   _vendored_dep(root, child, None, where))
    if out:
        notes["vendored"] = len(out)
    return out


def parse_js_banners(root, paths, notes):
    """Librerie JavaScript note copiate a mano, riconosciute dall'intestazione (vale anche con package.json)."""
    out, seen = [], set()
    for p in [p for p in paths if p.lower().endswith(".js")][:5000]:
        head = read(root, p, 600)
        m = JS_BANNER_RE.match(head)
        if m and m.group(1).strip().lower() in KNOWN_JS:
            name, version = m.group(1), m.group(2)
        else:
            # librerie senza nome nella prima riga, riconosciute dal testo dell'intestazione
            known = next(((n, b.group(1)) for n, rx_ in KNOWN_JS_TEXT if (b := rx_.search(head))), None)
            if not known:
                continue
            name, version = known
        key = (name.strip().lower(), version)
        if key not in seen:
            seen.add(key)
            out.append(_vendored_dep(root, name, version, p))
    if out:
        notes["vendored"] = notes.get("vendored", 0) + len(out)
    return out


def parse_debs(root, paths, notes):
    from .debpkg import read_control
    out = []
    for p in paths:
        if not p.endswith(".deb"):
            continue
        c = read_control(os.path.join(root, p))
        if c.get("Package"):
            # "artefatto": il file e' nel pacchetto analizzato, non scaricato da una fonte esterna
            out.append(D(c["Package"], c.get("Version"), "deb", supplier=c.get("Maintainer"), location=p,
                         source_kind="artefatto"))
    return out


# librerie spesso incorporate ("fat jar", "shaded") senza pom.properties: pacchetto -> (coordinate, licenza nota)
EMBEDDED_JAVA = [("junit/framework/", "junit:junit", "EPL-1.0"), ("org/junit/", "junit:junit", "EPL-1.0"),
                 ("org/hamcrest/", "org.hamcrest:hamcrest-core", "BSD-3-Clause"),
                 ("org/json/", "org.json:json", "JSON"),
                 ("com/google/gson/", "com.google.code.gson:gson", "Apache-2.0"),
                 ("org/apache/log4j/", "log4j:log4j", "Apache-2.0"),
                 ("org/apache/logging/log4j/core/", "org.apache.logging.log4j:log4j-core", "Apache-2.0"),
                 ("org/apache/commons/lang3/", "org.apache.commons:commons-lang3", "Apache-2.0"),
                 ("org/apache/commons/lang/", "commons-lang:commons-lang", "Apache-2.0"),
                 ("org/apache/commons/io/", "commons-io:commons-io", "Apache-2.0"),
                 ("org/apache/commons/codec/", "commons-codec:commons-codec", "Apache-2.0"),
                 ("org/apache/commons/collections/", "commons-collections:commons-collections", "Apache-2.0"),
                 ("org/apache/commons/fileupload/", "commons-fileupload:commons-fileupload", "Apache-2.0"),
                 ("org/apache/http/impl/client/", "org.apache.httpcomponents:httpclient", "Apache-2.0"),
                 ("com/fasterxml/jackson/databind/", "com.fasterxml.jackson.core:jackson-databind", "Apache-2.0"),
                 ("org/slf4j/", "org.slf4j:slf4j-api", "MIT"),
                 ("com/google/common/", "com.google.guava:guava", "Apache-2.0"),
                 ("org/bouncycastle/", "org.bouncycastle:bcprov-jdk15on", "MIT"),
                 ("org/dom4j/", "dom4j:dom4j", None),
                 ("org/yaml/snakeyaml/", "org.yaml:snakeyaml", "Apache-2.0"),
                 ("com/thoughtworks/xstream/", "com.thoughtworks.xstream:xstream", "BSD-3-Clause")]
# pacchetti di terzi: tutto il resto, in un jar, e' probabilmente codice del fornitore
THIRD_PARTY_JAVA = ("java/", "javax/", "jakarta/", "sun/", "com/sun/", "org/apache/", "org/w3c/", "org/xml/",
                    "org/omg/", "org/ietf/", "junit/", "org/junit/", "org/hamcrest/", "org/json/", "com/google/",
                    "org/slf4j/", "ch/qos/", "org/eclipse/", "org/springframework/", "com/fasterxml/", "org/codehaus/",
                    "net/sf/", "org/bouncycastle/", "kotlin/", "scala/", "org/dom4j/", "org/jdom", "org/yaml/",
                    "com/thoughtworks/", "org/hibernate/", "io/netty/", "org/objectweb/", "org/aopalliance/",
                    "org/mozilla/", "com/ibm/icu/", "org/glassfish/", "META-INF/", "org/osgi/", "org/jboss/")


def _jar_coords(data: bytes):
    """Coordinate di una libreria Java: pom.properties se c'e', altrimenti il MANIFEST.
    Restituisce (coordinate, jar annidati, librerie incorporate senza pom, pacchetti del fornitore)."""
    try:
        z = __import__("zipfile").ZipFile(io.BytesIO(data))
    except Exception:
        return [], [], [], {}
    found, nested = [], []
    classes = [n for n in z.namelist() if n.endswith(".class") and not n.startswith("META-INF/")]
    for n in z.namelist():
        if re.match(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$", n):
            props = dict(l.split("=", 1) for l in z.read(n).decode("utf-8", "ignore").splitlines()
                         if "=" in l and not l.startswith("#"))
            if props.get("groupId") and props.get("artifactId"):
                found.append((f"{props['groupId']}:{props['artifactId']}", props.get("version")))
        elif re.match(r"WEB-INF/lib/[^/]+\.jar$", n):
            nested.append((n, z.read(n)))
    if not found and "META-INF/MANIFEST.MF" in z.namelist():
        mf = z.read("META-INF/MANIFEST.MF").decode("utf-8", "ignore")
        title = rx(r"^(?:Implementation-Title|Bundle-SymbolicName):\s*([^;\r\n]+)", mf)
        ver = rx(r"^(?:Implementation-Version|Bundle-Version):\s*(\S+)", mf)
        if title:
            found.append((title.strip(), ver))
    names = {f[0] for f in found}
    # la libreria e' incorporata se ci sono classi DIRETTAMENTE nel suo pacchetto
    # (httpclient-cache ha org/apache/http/impl/client/cache/, che non e' httpclient)
    dirs = {c.rsplit("/", 1)[0] + "/" for c in classes}
    embedded, seen = [], set()
    for prefix, coord, lic in EMBEDDED_JAVA:
        if coord not in names and coord not in seen and prefix in dirs:
            seen.add(coord)
            embedded.append((coord, lic))
    # licenza del jar: il testo in META-INF/LICENSE (vale solo se il jar contiene una libreria sola)
    lic_file = next((n for n in z.namelist() if re.match(r"META-INF/LICEN[CS]E(\.txt|\.md)?$", n, re.I)), None)
    if lic_file and len(found) == 1:
        from .analyzers.governance import license_from_text
        found = [(found[0][0], found[0][1], license_from_text(z.read(lic_file)[:8000].decode("utf-8", "ignore").lower())
                  or None)]
    own = {}
    for c in classes:
        if not c.startswith(THIRD_PARTY_JAVA):
            pkg = c.rsplit("/", 1)[0] if "/" in c else "(pacchetto predefinito)"
            own[pkg] = own.get(pkg, 0) + 1
    return found, nested, embedded, own


def parse_jars(root, paths, notes):
    out = []
    for p in paths:
        if not p.lower().endswith((".jar", ".war", ".ear")):
            continue
        try:
            with open(os.path.join(root, p), "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        queue = [(p, data)]
        while queue:
            where, blob = queue.pop()
            coords, nested, embedded, own = _jar_coords(blob)
            digest = "sha256-" + base64.b64encode(hashlib.sha256(blob).digest()).decode()
            base = where.rsplit("/", 1)[-1]
            if not coords:                         # nessuna coordinata: almeno il nome del file
                m = re.match(r"(.+?)-(\d[\w.\-]*)\.(jar|war|ear)$", base)
                coords = [(m.group(1), m.group(2))] if m else []
            if not coords and own:                 # jar del fornitore senza versione: e' comunque un componente
                coords = [(re.sub(r"\.(jar|war|ear)$", "", base, flags=re.I), None)]
            for name, ver, *lic in coords:
                eco = "maven" if ":" in name else "generic"
                # l'impronta del file identifica il componente solo se il jar contiene quello e basta
                out.append(D(name, ver, eco, integrity=digest if len(coords) == 1 else None, location=where,
                             source_kind="artefatto", license=(lic or [None])[0],
                             license_from="META-INF/LICENSE del jar" if lic and lic[0] else None))
            for name, lic in embedded:             # incorporate senza pom.properties: versione ignota
                out.append(D(name, None, "maven", location=where, source_kind="artefatto", embedded=True,
                             license=lic, license_from="licenza nota della libreria" if lic else None))
            # classi del fornitore senza i sorgenti .java corrispondenti nel repository
            for pkg, n in sorted(own.items()):
                if not any(x.endswith(".java") and f"{pkg}/" in x for x in paths):
                    notes.setdefault("binary_only", []).append(f"{where};{pkg};{n}")
            queue += [(f"{where}!/{n}", b) for n, b in nested]
    return out


MAX_NESTED = 5
MAX_NESTED_BYTES = 200_000_000


def _safe_extract(zf, dest):
    """Estrae solo percorsi relativi senza '..' e entro il limite di dimensione."""
    total = 0
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if info.is_dir() or name.startswith("/") or ".." in name.split("/") or ":" in name:
            continue
        total += info.file_size
        if total > MAX_NESTED_BYTES:
            return False
        path = os.path.join(dest, *name.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with zf.open(info) as src, open(path, "wb") as out:
            out.write(src.read())
    return True


def parse_nested_archives(root, paths, notes):
    """Pacchetti .zip dentro i sorgenti (es. lo zimlet pronto da installare): spesso e' QUESTO che va in
    produzione. Se esiste la cartella con lo stesso nome si confronta il contenuto file per file;
    se manca, o il contenuto e' diverso, il pacchetto viene aperto e analizzato a sua volta."""
    import tempfile
    import zipfile
    out = []
    for p in [p for p in paths if p.lower().endswith(".zip")][:MAX_NESTED]:
        try:
            zf = zipfile.ZipFile(os.path.join(root, p))
            entries = [i for i in zf.infolist() if not i.is_dir()]
        except (OSError, zipfile.BadZipFile):
            notes.setdefault("nested", []).append(f"{p};illeggibile;archivio non valido")
            continue
        stem = p[:-4]
        names = [i.filename for i in entries]
        top = {n.split("/")[0] for n in names}
        strip = len(top) == 1 and all("/" in n for n in names) and top == {stem.rsplit("/", 1)[-1]}
        status, detail = "non confrontabile", "nessuna cartella con lo stesso nome nei sorgenti"
        if os.path.isdir(os.path.join(root, stem)):
            diff, missing = [], []
            for i in entries:
                rel = i.filename.split("/", 1)[1] if strip else i.filename
                src = os.path.join(root, stem, *rel.split("/"))
                if not os.path.isfile(src):
                    missing.append(rel)
                else:
                    with open(src, "rb") as fh:
                        if hashlib.sha256(fh.read()).digest() != hashlib.sha256(zf.read(i)).digest():
                            diff.append(rel)
            if not diff and not missing:
                status, detail = "identico", f"alla cartella {stem}/ ({len(entries)} file)"
            else:
                status = "diverso"
                detail = (f"rispetto a {stem}/: {len(diff)} file diversi, {len(missing)} solo nel pacchetto"
                          + (f" (es. {(diff + missing)[0]})" if diff or missing else ""))
        notes.setdefault("nested", []).append(f"{p};{status};{detail}")
        if status == "identico":
            continue
        with tempfile.TemporaryDirectory(prefix="sovrasbom-nested-") as tmp:
            if not _safe_extract(zf, tmp):
                continue
            inner_paths = list_files(tmp)
            inner_notes = {"unsupported": [], "replaces": [], "index_urls": [], "vendored": 0}
            for fn in PARSERS:
                if fn is parse_nested_archives:      # un solo livello di annidamento
                    continue
                for d in fn(tmp, inner_paths, inner_notes):
                    d["location"] = f"{p}!/{d['location']}" if d.get("location") else f"{p}!/"
                    out.append(d)
    return out


PARSERS = (parse_debs, parse_jars, parse_npm, parse_go, parse_python, parse_cargo, parse_composer, parse_maven,
           parse_gradle, parse_gem, parse_nuget, parse_vcpkg_conan, parse_cc_vendored, parse_js_banners,
           parse_nested_archives)


def project_version(root, paths) -> tuple:
    """Versione dichiarata del software analizzato: (versione, file) dal manifest meno annidato."""
    candidates = []
    for p in paths:
        b = p.rsplit("/", 1)[-1]
        depth = p.count("/")
        if b == "package.json" and "node_modules/" not in p:
            v = rx(r'^\s{0,4}"version"\s*:\s*"([^"]+)"', read(root, p, 4000))
        elif b in ("pyproject.toml", "Cargo.toml"):
            v = rx(r'^version\s*=\s*"([^"]+)"', read(root, p, 8000))
        elif b == "pom.xml":
            text = re.sub(r"(?s)<parent>.*?</parent>|<dependencies>.*", "", read(root, p, 20000))
            v = rx(r"<version>([^<$]+)</version>", text)
        elif b.lower() in ("publiccode.yml", "publiccode.yaml"):
            v = rx(r"^softwareVersion:\s*['\"]?([^'\"\s]+)", read(root, p, 8000))
        elif b.endswith(".xml") and depth <= 2:
            # descrittore di uno zimlet Zimbra: <zimlet name="..." version="2.0">
            v = rx(r"<zimlet\s[^>]*\bversion=\"([^\"]+)\"", read(root, p, 4000))
        else:
            v = None
        if v:
            candidates.append((depth, p, v.strip()))
    if not candidates:
        return "", ""
    depth, p, v = min(candidates)
    return v, p


def collect(root: str):
    """Legge tutti i file di dipendenze: restituisce (dipendenze senza duplicati, note)."""
    paths = list_files(root)
    notes = {"unsupported": [], "replaces": [], "index_urls": [], "vendored": 0}
    deps, seen = [], set()
    for fn in PARSERS:
        for d in fn(root, paths, notes):
            key = (d["eco"], d["name"], d["version"])
            if key not in seen:
                seen.add(key)
                deps.append(d)
            elif d["source_kind"] == "copiato":       # stessa libreria vista dalla cartella e dall'intestazione
                notes["vendored"] -= 1
    return deps, notes


def license_entry(lic: str) -> dict:
    """CycloneDX accetta in "id" solo identificativi SPDX: tutto il resto va in "name" (o "expression")."""
    from .analyzers.licenses import OPEN_CATEGORIES, classify_token
    if re.search(r"\s(AND|OR|WITH)\s", lic, re.I):
        return {"expression": lic}
    if re.fullmatch(r"[A-Za-z0-9.\-+]+", lic) and classify_token(lic) in OPEN_CATEGORIES:
        return {"license": {"id": lic}}
    return {"license": {"name": lic}}


# ============================================================ SBOM CycloneDX
def generate(root: str, project: str, out_path: str) -> int:
    """Scrive una SBOM CycloneDX 1.5 e restituisce il numero di componenti trovati."""
    deps, notes = collect(root)
    version, version_file = project_version(root, list_files(root))
    comps, direct = [], []
    for x in deps:
        c = {"type": "library", "bom-ref": x["purl"], "name": x["name"], "purl": x["purl"]}
        if x["version"]:
            c["version"] = x["version"]
        if x["license"]:
            c["licenses"] = [license_entry(x["license"])]
        h = to_hash(x["integrity"])
        if h:
            c["hashes"] = [{"alg": h[0], "content": h[1]}]
        if x["dev"]:
            c["scope"] = "optional"
        if x.get("supplier"):
            c["supplier"] = {"name": x["supplier"]}
        c["properties"] = [{"name": "sovrasbom:source", "value": x["source_kind"]}]
        if x["hashable"]:
            c["properties"].append({"name": "sovrasbom:hashable", "value": "true"})
        if x.get("license_from"):
            c["properties"].append({"name": "sovrasbom:license-source", "value": x["license_from"]})
        if x["source_kind"] == "copiato" and h:
            c["properties"].append({"name": "sovrasbom:hash-scope",
                                    "value": "contenuto della copia: SHA-256 dell'elenco ordinato percorso + SHA-256"})
        if x.get("embedded"):
            c["properties"].append({"name": "sovrasbom:embedded",
                                    "value": "classi incorporate in un altro jar, versione non dichiarata"})
        if x.get("resolved") and x["source_kind"] != "registry":
            c["properties"].append({"name": "sovrasbom:resolved", "value": x["resolved"]})
        if x.get("location"):
            c["properties"].append({"name": "syft:location:0:path", "value": x["location"]})
        comps.append(c)
        if x["direct"]:
            direct.append(x["purl"])
    # note del motore (file non letti, indici alternativi, replace): finiscono nel report
    note_props = [{"name": f"sovrasbom:note:{k}", "value": str(v)}
                  for k, vals in notes.items() for v in (vals if isinstance(vals, list) else [vals]) if v]
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "tools": {"components": [{"type": "application", "name": "sovrasbom-integrato",
                                               "version": "lettura dei file di dipendenze"}]},
                     "component": dict({"type": "application", "name": project, "bom-ref": "root"},
                                       **({"version": version} if version else {})),
                     "properties": note_props + ([{"name": "sovrasbom:version-source", "value": version_file}]
                                                 if version else [])},
        "components": comps,
        "dependencies": [{"ref": "root", "dependsOn": sorted(set(direct))}] if direct else [],
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(bom, fh, indent=1)
    return len(comps)


def add_registry_data(out_path: str, components: list) -> int:
    """Riporta nella SBOM generata le licenze ricavate da deps.dev, con la fonte dichiarata:
    cosi' i numeri del report si ricalcolano dalla SBOM allegata alle evidenze."""
    with open(out_path, encoding="utf-8") as fh:
        bom = json.load(fh)
    by_purl = {c.purl: c for c in components if c.license_source == "deps.dev" and c.licenses}
    n = 0
    for c in bom.get("components", []):
        comp = by_purl.get(c.get("purl"))
        if comp and not c.get("licenses"):
            c["licenses"] = [license_entry(l) for l in comp.licenses]
            c.setdefault("properties", []).append({"name": "sovrasbom:license-source", "value": "deps.dev"})
            n += 1
    if n:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(bom, fh, indent=1)
    return n
