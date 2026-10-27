"""Rilasci GitHub: analizza il binario PUBBLICATO, cioe' quello che una PA scarica e installa.

Esempio: https://github.com/maldua/zimbra-foss/releases/tag/zimbra-foss-build-ubuntu-24.04%2F10.1.20.p1

Passi:
1. chiede a GitHub l'elenco dei file del rilascio (API pubblica, nessuna chiave;
   con la variabile GITHUB_TOKEN si alzano i limiti di 60 richieste/ora)
2. sceglie l'archivio principale (o quello indicato con --asset) e lo scarica
3. verifica l'impronta SHA-256 con DUE fonti distinte, se disponibili:
   - il file .sha256 / checksums pubblicato dall'autore nello stesso rilascio
   - il "digest" che GitHub calcola da solo quando il file viene caricato
4. registra se esistono firme o attestazioni (.asc, .sig, .sigstore, .intoto.jsonl...)
5. estrae l'archivio e apre i pacchetti .deb, poi clona il repository allo stesso tag:
   SBOM e vulnerabilita' dal binario, governance e pipeline dal codice che lo produce
"""

import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from urllib.parse import quote, unquote

API = os.environ.get("SOVRASBOM_GITHUB_API", "https://api.github.com")
ARCHIVE_EXT = (".tgz", ".tar.gz", ".tar.xz", ".tar.bz2", ".zip", ".deb", ".rpm")
SIG_EXT = (".asc", ".sig", ".minisig", ".sigstore", ".sigstore.json", ".intoto.jsonl", ".pem", ".cert",
           ".bundle")
RELEASE_RE = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)/releases/tag/(.+?)/?$")


def parse_release_url(arg: str):
    m = RELEASE_RE.match(arg.split("#")[0].split("?")[0])
    return (m.group(1), m.group(2), unquote(m.group(3))) if m else None


def _request(url, accept="application/vnd.github+json"):
    headers = {"User-Agent": "sovrasbom", "Accept": accept}
    if os.environ.get("GITHUB_TOKEN") and url.startswith(API):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60)


def fetch_release(owner, repo, tag) -> dict:
    url = f"{API}/repos/{owner}/{repo}/releases/tags/{quote(tag, safe='')}"
    try:
        with _request(url) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError(f"rilascio '{tag}' non trovato in {owner}/{repo}")
        if e.code in (403, 429):
            raise RuntimeError("limite di richieste alle API GitHub raggiunto: riprova tra un'ora oppure "
                               "imposta la variabile GITHUB_TOKEN; in alternativa scarica il file a mano "
                               "e passalo al tool")
        raise RuntimeError(f"API GitHub: errore {e.code}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"API GitHub non raggiungibile ({e.reason})")


def choose_asset(assets: list, wanted: str = "") -> dict:
    if wanted:
        for a in assets:
            if a["name"] == wanted:
                return a
        raise RuntimeError(f"il rilascio non contiene '{wanted}'. File disponibili: "
                           + ", ".join(a["name"] for a in assets))
    archives = [a for a in assets if a["name"].lower().endswith(ARCHIVE_EXT)
                and "source" not in a["name"].lower()]
    if not archives:
        raise RuntimeError("nessun archivio nel rilascio. File disponibili: "
                           + ", ".join(a["name"] for a in assets) + " (usa --asset NOME)")
    return max(archives, key=lambda a: a.get("size", 0))      # di solito il binario e' il file piu' grande


def download(url: str, dest: str, size: int, log) -> str:
    """Scarica calcolando l'impronta mentre scrive (non serve rileggere il file)."""
    h = hashlib.sha256()
    done, next_mark = 0, 0.25
    with _request(url, accept="application/octet-stream") as r, open(dest, "wb") as out:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
            h.update(chunk)
            done += len(chunk)
            if size and done / size >= next_mark:
                log(f"  scaricato {int(100 * done / size)}% di {size // 1024 ** 2} MB")
                next_mark += 0.25
    return h.hexdigest()


def published_checksum(assets: list, asset_name: str):
    """Cerca l'impronta dichiarata dall'autore: <nome>.sha256, SHA256SUMS, *checksums*.txt ..."""
    low = asset_name.lower()
    candidates = [a for a in assets if a["name"].lower() in (low + ".sha256", low + ".sha256sum", low + ".sha256.txt")]
    candidates += [a for a in assets if a["name"].lower() in ("sha256sums", "sha256sums.txt", "checksums.txt")
                   or ("checksum" in a["name"].lower() and a["name"].lower().endswith(".txt"))]
    for a in candidates:
        if a.get("size", 0) > 1_000_000:
            continue
        try:
            with _request(a["browser_download_url"], accept="application/octet-stream") as r:
                text = r.read().decode("utf-8", "ignore")
        except Exception:
            continue
        lines = [l for l in text.splitlines() if l.strip()]
        for line in lines:
            m = re.search(r"\b([0-9a-fA-F]{64})\b", line)
            if m and (asset_name in line or len(lines) == 1):
                return m.group(1).lower(), a["name"]
    return None, ""


def build_target(arg: str, log, asset_name: str = ""):
    from .target import Target, _extract_tree, _from_git     # import qui per evitare cicli

    owner, repo, tag = parse_release_url(arg)
    log(f"Leggo il rilascio '{tag}' di {owner}/{repo}...")
    rel = fetch_release(owner, repo, tag)
    assets = rel.get("assets") or []
    asset = choose_asset(assets, asset_name)
    tmp = tempfile.mkdtemp(prefix="sovrasbom-rel-")
    path = os.path.join(tmp, asset["name"])
    log(f"Scarico {asset['name']}...")
    sha = download(asset["browser_download_url"], path, asset.get("size", 0), log)

    declared, declared_from = published_checksum(assets, asset["name"])
    gh_digest = (asset.get("digest") or "").split(":", 1)[-1].lower() if (asset.get("digest") or "").startswith("sha256:") else ""
    signatures = [a["name"] for a in assets if a["name"].lower().endswith(SIG_EXT)]
    info = {
        "owner": owner, "repo": repo, "tag": tag,
        "url": rel.get("html_url", arg),
        "published_at": rel.get("published_at", ""),
        "author": (rel.get("author") or {}).get("login", ""),
        "prerelease": bool(rel.get("prerelease")),
        "asset": asset["name"], "size": asset.get("size", 0), "sha256": sha,
        "declared_sha256": declared, "declared_from": declared_from,
        "checksum_match": (declared == sha) if declared else None,
        "github_digest": gh_digest,
        "github_digest_match": (gh_digest == sha) if gh_digest else None,
        "signatures": signatures,
        "other_assets": [a["name"] for a in assets if a["name"] != asset["name"]],
    }
    if info["checksum_match"] is False or info["github_digest_match"] is False:
        log("ATTENZIONE: l'impronta del file scaricato NON corrisponde a quella pubblicata!")
    else:
        log("Impronta verificata: " + ", ".join(
            x for x in [f"file {declared_from}" if info["checksum_match"] else "",
                        "digest calcolato da GitHub" if info["github_digest_match"] else ""] if x)
            if (info["checksum_match"] or info["github_digest_match"]) else
            "Nessuna impronta pubblicata con cui confrontare il file")

    files_root, pkg = _extract_tree(path, tmp, log)
    t = Target(kind="rilascio", label=f"rilascio {tag} di {owner}/{repo} · {asset['name']}",
               name=f"{repo} rilascio {tag}", scan_source=f"dir:{files_root}", root="",
               files_root=files_root, temp_dirs=[tmp])
    t.extra["release"] = info
    t.extra["archive_sha256"] = sha
    t.extra["packages"] = pkg
    # il codice che produce il rilascio: stesso tag, stesso repository
    try:
        src = _from_git(f"https://github.com/{owner}/{repo}", tag, log)
        t.root, t.git = src.root, src.git
        t.temp_dirs += src.temp_dirs
    except RuntimeError as exc:
        log(f"Repository non clonato ({exc}): salto governance e pipeline")
    return t
