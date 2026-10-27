"""Arricchimento online con deps.dev (Google Open Source Insights): gratis, senza chiave.

Per ogni dipendenza presa da un registro pubblico chiede:
- date delle versioni (ultima release, quindi se il pacchetto e' ancora mantenuto)
- deprecazione, numero di advisory note sulla versione usata
- licenze dichiarate nel registro (se la SBOM non le riporta)
- repository sorgente collegato e attestazioni di provenienza (SLSA)
Se un pacchetto non esiste nel registro pubblico e' un indizio di "dependency confusion"
(un nome interno che qualcuno potrebbe registrare sul registro pubblico).

Ripreso da sovereignty_check.py. Le risposte vanno in una cache su disco
(~/.cache/sovrasbom/depsdev.json, valida 7 giorni) per non ripetere le stesse
richieste a ogni analisi. Con --offline il modulo non viene usato.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

DEPSDEV = "https://api.deps.dev/v3"
PURL_TO_SYSTEM = {"npm": "NPM", "golang": "GO", "pypi": "PYPI", "cargo": "CARGO", "maven": "MAVEN",
                  "gem": "RUBYGEMS", "nuget": "NUGET"}
CACHE_PATH = os.path.join(os.path.expanduser("~"), ".cache", "sovrasbom", "depsdev.json")
CACHE_TTL = 7 * 86400
# provenienze per cui ha senso chiedere al registro pubblico (git e percorsi locali non ci sono;
# le librerie note copiate a mano si', con il nome del pacchetto npm corrispondente, e cosi' i jar inclusi
# nell'artefatto che dichiarano le coordinate Maven: sono gli stessi pubblicati su Maven Central)
QUERYABLE_SOURCES = ("", "registry", "altra fonte", "copiato", "artefatto")

_cache, _lock = {}, threading.Lock()


def _days_since(iso):
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - t).days


def http_json(url):
    """GET con cache su disco; None se la risorsa non esiste (404)."""
    with _lock:
        hit = _cache.get(url)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1]
    req = urllib.request.Request(url, headers={"User-Agent": "sovrasbom", "Accept": "application/json"})
    data = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                break
            if e.code in (429, 503) and attempt == 0:
                time.sleep(2)
                continue
            raise
    with _lock:
        _cache[url] = [time.time(), data]
    return data


def package_key(purl: str):
    """(sistema deps.dev, nome, versione) dal purl, oppure None se l'ecosistema non e' supportato."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body, _, version = purl[4:].split("?")[0].split("#")[0].partition("@")
    parts = [urllib.parse.unquote(p) for p in body.split("/") if p]
    if len(parts) < 2 or parts[0] not in PURL_TO_SYSTEM:
        return None
    ptype, rest = parts[0], parts[1:]
    name = f"{rest[0]}:{rest[1]}" if ptype == "maven" and len(rest) == 2 else "/".join(rest)
    return PURL_TO_SYSTEM[ptype], name, urllib.parse.unquote(version)


def enrich_one(comp):
    key = package_key(comp.purl)
    if not key:
        comp.registry = {"net": "non supportato"}
        return
    system, name, version = key
    reg = {"net": "ok", "system": system}
    try:
        qname = urllib.parse.quote(name, safe="")
        pk = http_json(f"{DEPSDEV}/systems/{system}/packages/{qname}")
        if not pk:
            comp.registry = {"net": "non trovato", "system": system}
            return
        vers = pk.get("versions") or []
        vk = lambda v: (v.get("versionKey") or {}).get("version")
        latest = next((v for v in vers if v.get("isDefault")), None) or \
            (max(vers, key=lambda v: v.get("publishedAt") or "") if vers else None)
        used = next((v for v in vers if vk(v) == version), None) if version else None
        reg["latest"] = vk(latest) if latest else None
        # "mantenuto" = qualunque release recente, non solo la versione predefinita del registro
        # (per Maven la predefinita puo' essere una vecchia alpha con numero piu' alto)
        newest = max((v.get("publishedAt") or "" for v in vers), default="")
        reg["latest_days"] = _days_since(newest) if newest else None
        reg["version_found"] = used is not None
        ver = version if used else reg["latest"]
        vi = http_json(f"{DEPSDEV}/systems/{system}/packages/{qname}/versions/"
                       f"{urllib.parse.quote(ver, safe='')}") if ver else None
        ref = vi or used or latest or {}
        reg["deprecated"] = bool(ref.get("isDeprecated") or ref.get("deprecatedReason"))
        if vi:
            # "non-standard": deps.dev non ha saputo leggere la licenza del POM, non e' un dato
            reg["licenses"] = [l for l in vi.get("licenses") or [] if l.lower() not in ("non-standard", "noassertion")]
            reg["advisories"] = [a.get("id") for a in vi.get("advisoryKeys") or [] if a.get("id")] if used else []
            reg["has_source"] = bool(vi.get("relatedProjects")) or any(
                l.get("label") == "SOURCE_REPO" for l in vi.get("links") or [])
            reg["attested"] = bool(vi.get("attestations") or vi.get("slsaProvenances"))
        if not comp.licenses and reg.get("licenses"):
            # licenza ricavata dal registro (della versione usata, o dell'ultima se la versione non e'
            # nota): va dichiarato da dove viene
            comp.licenses = [" AND ".join(reg["licenses"])]
            comp.license_source = "deps.dev"
    except Exception as exc:  # rete assente, limiti del servizio, risposta inattesa
        reg = {"net": "errore", "error": str(exc)[:80]}
    comp.registry = reg


def _load_cache():
    try:
        with open(CACHE_PATH, encoding="utf-8") as fh:
            _cache.update(json.load(fh))
    except (OSError, ValueError):
        pass


def _save_cache():
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(_cache, fh)
    except OSError:
        pass


def enrich(components: list, max_deps: int = 80) -> dict:
    """Interroga deps.dev per le dipendenze dai registri pubblici: prima le dirette non di sviluppo.

    max_deps limita il numero di pacchetti interrogati (0 = tutti).
    """
    _load_cache()
    cand = [c for c in components if not c.dev and c.source_kind in QUERYABLE_SOURCES and package_key(c.purl)
            and not (c.source_kind == "artefatto" and not c.version)]   # incorporate senza versione: dato inutile
    cand.sort(key=lambda c: 0 if c.direct else (1 if c.direct is None else 2))
    skipped = len(cand) - max_deps if max_deps and len(cand) > max_deps else 0
    if max_deps:
        cand = cand[:max_deps]
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(enrich_one, cand))
    _save_cache()
    c = Counter(x.registry.get("net") for x in cand)
    return {"queried": len(cand), "ok": c["ok"], "errors": c["errore"], "not_found": c["non trovato"],
            "skipped": skipped, "licenses_added": sum(1 for x in cand if x.license_source == "deps.dev")}
