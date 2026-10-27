"""Riconoscimento automatico dell'input: un solo argomento, qualunque cosa sia.

Idea presa da sovereignty_check.py: chi usa il tool scrive solo
    python3 analizza.py <cosa-analizzare>
e il programma capisce da solo se si tratta di:
  - una cartella (sorgenti o software installato, es. /opt/zimbra)
  - un archivio .zip / .tar.gz (lo estrae in una cartella temporanea)
  - un repository Git: URL completo, anche con /tree/<tag>, oppure owner/repo
  - una SBOM gia' pronta (CycloneDX JSON/XML, SPDX JSON/tag-value)
  - un'immagine container o una sorgente Syft (docker:..., registry:..., dir:...)

Sicurezza: il codice scaricato viene solo LETTO, mai eseguito. git clone non esegue
script del repository e gli archivi vengono estratti rifiutando percorsi che escono
dalla cartella di destinazione.
"""

import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import unquote, urlsplit, urlunsplit

SCAN_SCHEMES = ("dir:", "docker:", "podman:", "registry:", "oci-archive:", "oci-dir:",
                "docker-archive:", "singularity:", "file:")
# segmenti che nelle pagine web dei servizi Git separano il repository dal riferimento
REF_MARKERS = ("/-/tree/", "/-/blob/", "/tree/", "/blob/", "/src/branch/", "/src/tag/",
               "/src/commit/", "/commit/", "/releases/tag/")
GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")


@dataclass
class Target:
    kind: str                 # cartella | archivio | git | sbom | immagine | file
    label: str                # descrizione per le evidenze
    name: str                 # nome proposto per il titolo della presentazione
    scan_source: str = ""     # sorgente per Syft/Trivy (es. dir:/percorso); vuota per una SBOM
    sbom_path: str = ""       # se l'input e' gia' una SBOM
    root: str = ""            # cartella del codice sorgente: serve a governance e pipeline
    git: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)
    temp_dirs: list = field(default_factory=list)
    files_root: str = ""      # cartella con i file del software (per un rilascio: il binario estratto)

    def __post_init__(self):
        self.files_root = self.files_root or self.root

    def cleanup(self):
        for d in self.temp_dirs:
            shutil.rmtree(d, ignore_errors=True)


# ============================================================ utilita'
def _git(root, *args):
    res = subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, env=GIT_ENV)
    return res.stdout.strip() if res.returncode == 0 else ""


def clean_url(url: str) -> str:
    """Toglie eventuali credenziali dall'URL (https://utente:token@host/...) prima di scriverlo nel report."""
    try:
        parts = urlsplit(url)
        if parts.username or parts.password:
            host = parts.hostname + (f":{parts.port}" if parts.port else "")
            return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    except ValueError:
        pass
    return url


def git_info(root: str) -> dict:
    """Identita' esatta del codice (commit) e segnali dallo storico (chi lo mantiene, da quando)."""
    if not (shutil.which("git") and os.path.exists(os.path.join(root, ".git"))):
        return {}
    commit = _git(root, "rev-parse", "HEAD")
    if not commit:
        return {}
    info = {
        "commit": commit,
        "commit_date": _git(root, "log", "-1", "--format=%cI"),
        "remote": clean_url(_git(root, "remote", "get-url", "origin")),
        "tags_here": _git(root, "tag", "--points-at", "HEAD").split(),
        "shallow": _git(root, "rev-parse", "--is-shallow-repository") == "true",
    }
    # Ultimi 500 commit: quante persone scrivono il codice e quanto pesa la prima.
    # Se una sola persona fa quasi tutto, il progetto dipende da lei ("bus factor").
    lines = [l for l in _git(root, "log", "-n", "500", "--format=%aN|%cI").splitlines() if "|" in l]
    if lines and not info["shallow"]:
        authors = Counter(l.split("|")[0] for l in lines)
        info["history"] = {
            "commits": len(lines),
            "authors": len(authors),
            "top_author_share": authors.most_common(1)[0][1] / len(lines),
            "oldest_date": lines[-1].split("|")[1],
        }
    last_tag = _git(root, "describe", "--tags", "--abbrev=0")
    if last_tag:
        info["last_tag"] = last_tag
        info["last_tag_date"] = _git(root, "log", "-1", "--format=%cI", last_tag)
    return info


def days_since(iso: str):
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - t).days


# ============================================================ riconoscimento
def _looks_like_sbom(path: str) -> bool:
    from .sbom import looks_like_sbom
    return looks_like_sbom(path)


def parse_git_url(arg: str):
    """Restituisce (url_clonabile, riferimento_candidato) oppure (None, None)."""
    if arg.startswith((".", "/", "~")):
        return None, None                                          # e' un percorso locale, non un repository
    if re.fullmatch(r"[\w-][\w.-]*/[\w.-]+", arg) and not os.path.exists(arg):
        return f"https://github.com/{arg}", ""                    # scorciatoia owner/repo
    if arg.startswith("git@") or arg.startswith("ssh://"):
        return arg, ""
    if not re.match(r"https?://", arg):
        return None, None
    url = arg.split("#")[0].split("?")[0].rstrip("/")
    for marker in REF_MARKERS:
        if marker in url:
            repo, ref = url.split(marker, 1)
            return repo, unquote(ref)                              # il ref puo' contenere "/" (anche come %2F)
    return url, ""


def resolve_ref(url: str, candidate: str) -> str:
    """Da 'zimbra-foss-build-ubuntu-24.04/10.1.20.p1/docs' ricava il tag o branch reale.

    Perche': nei nomi dei tag possono esserci delle "/" (come in quelli di Maldua) e
    negli URL delle pagine web dopo il ref puo' seguire un percorso. Chiediamo al server
    l'elenco dei riferimenti e scegliamo il prefisso piu' lungo che esiste davvero.
    """
    if not candidate:
        return ""
    if re.fullmatch(r"[0-9a-fA-F]{7,40}", candidate.split("/")[0]):
        return candidate.split("/")[0]                             # e' l'hash di un commit
    res = subprocess.run(["git", "ls-remote", "--heads", "--tags", url],
                         capture_output=True, text=True, env=GIT_ENV, timeout=120)
    names = set()
    for line in res.stdout.splitlines():
        ref = line.split("\t")[-1].replace("^{}", "")
        for prefix in ("refs/heads/", "refs/tags/"):
            if ref.startswith(prefix):
                names.add(ref[len(prefix):])
    parts = candidate.split("/")
    for n in range(len(parts), 0, -1):
        if "/".join(parts[:n]) in names:
            return "/".join(parts[:n])
    if res.returncode != 0:
        return candidate                                           # server non raggiungibile: proviamo comunque
    raise ValueError(f"il riferimento '{candidate}' non esiste in {clean_url(url)}")


def _repo_name(url: str) -> str:
    return re.sub(r"\.git$", "", url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]) or "repository"


def _from_git(url: str, ref: str, log) -> Target:
    if not shutil.which("git"):
        raise RuntimeError("per analizzare un repository serve git installato")
    tmp = tempfile.mkdtemp(prefix="sovrasbom-git-")
    dest = os.path.join(tmp, _repo_name(url))
    is_sha = bool(re.fullmatch(r"[0-9a-fA-F]{7,40}", ref or ""))
    branch = ["--branch", ref] if ref and not is_sha else []
    log(f"Clono {clean_url(url)}" + (f" al riferimento {ref}" if ref else "") + "...")
    # Clone "parziale" (--filter=blob:none): scarica tutta la storia dei commit, che serve
    # a misurare chi mantiene il progetto, ma solo i file della versione richiesta.
    attempts = [["git", "clone", "--quiet", "--filter=blob:none", *branch, url, dest],
                ["git", "clone", "--quiet", "--depth", "1", *branch, url, dest]]
    if is_sha:
        attempts = attempts[:1] + [["git", "clone", "--quiet", url, dest]]
    err = ""
    for cmd in attempts:
        shutil.rmtree(dest, ignore_errors=True)
        res = subprocess.run(cmd, capture_output=True, text=True, env=GIT_ENV)
        if res.returncode == 0:
            break
        err = res.stderr.strip()
    else:
        shutil.rmtree(tmp, ignore_errors=True)
        if re.search(r"could not read Username|Authentication failed|not found|returned error: 40[134]", err):
            raise RuntimeError(f"il repository {clean_url(url)} non esiste, è privato o l'URL è sbagliato")
        raise RuntimeError(f"clone non riuscito: {err.splitlines()[-1][:200] if err else 'errore sconosciuto'}")
    if is_sha:
        _git(dest, "checkout", "--quiet", ref)
        if not _git(dest, "rev-parse", "HEAD").startswith(ref.lower()):
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"commit {ref} non trovato nel repository")
    info = git_info(dest)
    info["url"] = clean_url(url)
    info["ref"] = ref or "branch principale"
    short = info.get("commit", "")[:7]
    return Target(kind="git", label=f"{clean_url(url)} @ {info['ref']} ({short})",
                  name=f"{_repo_name(url)} @ {ref}" if ref else _repo_name(url),
                  scan_source=f"dir:{dest}", root=dest, git=info, temp_dirs=[tmp])


def _from_dir(path: str) -> Target:
    info = git_info(path)
    short = info.get("commit", "")[:7]
    name = os.path.basename(path.rstrip("/")) or path
    if info:
        info["url"] = info.get("remote") or "repository locale"
        info["ref"] = (info.get("tags_here") or [""])[0] or "copia locale"
    return Target(kind="cartella", label=path + (f" (commit {short})" if short else ""),
                  name=name + (f" ({short})" if short else ""), scan_source=f"dir:{path}",
                  root=path, git=info)


def _safe_extract(archive: str, dest: str):
    """Estrae rifiutando percorsi assoluti o con '..' (attacco "zip slip")."""
    real_dest = os.path.realpath(dest)
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                target = os.path.realpath(os.path.join(dest, name))
                if not target.startswith(real_dest + os.sep) and target != real_dest:
                    raise RuntimeError(f"percorso non sicuro nell'archivio: {name}")
            zf.extractall(dest)
        return
    with tarfile.open(archive) as tf:
        try:
            tf.extractall(dest, filter="data")   # Python 3.12+: blocca link e percorsi pericolosi
        except TypeError:
            for m in tf.getmembers():
                target = os.path.realpath(os.path.join(dest, m.name))
                if not target.startswith(real_dest + os.sep) or m.issym() or m.islnk() or m.isdev():
                    raise RuntimeError(f"elemento non sicuro nell'archivio: {m.name}")
            tf.extractall(dest)


def _extract_tree(path: str, workdir: str, log):
    """Estrae l'archivio in workdir/estratto e apre gli eventuali pacchetti .deb contenuti."""
    from .debpkg import expand_debs
    dest = os.path.join(workdir, "estratto")
    os.makedirs(dest, exist_ok=True)
    if path.lower().endswith(".deb"):
        shutil.copy(path, dest)                       # un singolo pacchetto: lo apriamo direttamente
    else:
        log(f"Estraggo {os.path.basename(path)}...")
        _safe_extract(path, dest)
    items = os.listdir(dest)
    root = os.path.join(dest, items[0]) if len(items) == 1 and os.path.isdir(os.path.join(dest, items[0])) else dest
    pkg = expand_debs(root, log)
    if pkg["debs"]:
        log(f"Pacchetti .deb: {pkg['debs']}, aperti: {pkg['expanded']}"
            + (f", non aperti: {len(pkg['skipped'])}" if pkg["skipped"] else ""))
    return root, pkg


def _from_archive(path: str, log) -> Target:
    from .collect import sha256_file
    tmp = tempfile.mkdtemp(prefix="sovrasbom-arc-")
    root, pkg = _extract_tree(path, tmp, log)
    base = re.sub(r"\.(zip|tar|tgz|tar\.gz|tar\.bz2|tar\.xz|deb)$", "", os.path.basename(path), flags=re.I)
    # un archivio di pacchetti e' un binario, non codice sorgente: niente governance/pipeline
    src_root = "" if pkg["debs"] else root
    t = Target(kind="archivio", label=os.path.basename(path), name=base, scan_source=f"dir:{root}",
               root=src_root, files_root=root, git=git_info(root), temp_dirs=[tmp])
    t.extra["archive_sha256"] = sha256_file(path)
    t.extra["packages"] = pkg
    return t


def resolve(arg: str, ref: str = "", log=print, asset: str = "") -> Target:
    """Punto di ingresso: capisce che cosa e' `arg` e prepara i file da analizzare."""
    from . import release
    if release.parse_release_url(arg):
        return release.build_target(arg, log, asset)
    if arg.startswith(SCAN_SCHEMES):
        if arg.startswith("dir:") and os.path.isdir(arg[4:]):
            return _from_dir(os.path.abspath(arg[4:]))
        kind = "file" if arg.startswith("file:") else "immagine"
        return Target(kind=kind, label=arg, name=arg.split(":", 1)[1], scan_source=arg)
    if os.path.isdir(arg):
        return _from_dir(os.path.abspath(arg))
    if os.path.isfile(arg):
        if _looks_like_sbom(arg):
            return Target(kind="sbom", label=f"SBOM {os.path.basename(arg)}",
                          name=re.sub(r"(\.(cdx|spdx|bom|sbom))?\.(json|xml|spdx|tv|txt)$", "", os.path.basename(arg)),
                          sbom_path=arg)
        if zipfile.is_zipfile(arg) or tarfile.is_tarfile(arg) or arg.lower().endswith(".deb"):
            return _from_archive(arg, log)
        return Target(kind="file", label=arg, name=os.path.basename(arg), scan_source=f"file:{os.path.abspath(arg)}")
    url, ref_from_url = parse_git_url(arg)
    if url:
        chosen = ref or resolve_ref(url, ref_from_url)
        return _from_git(url, chosen, log)
    if arg.startswith((".", "/", "~")):
        raise ValueError(f"'{arg}' non esiste: controlla il percorso")
    raise ValueError(
        f"non riconosco '{arg}'. Puoi passare: una cartella, un archivio .zip/.tar.gz/.deb, "
        "un URL Git (anche https://github.com/owner/repo/tree/<tag>), un rilascio GitHub "
        "(https://github.com/owner/repo/releases/tag/<tag>), owner/repo, "
        "una SBOM (CycloneDX/SPDX), oppure docker:immagine:tag"
    )
