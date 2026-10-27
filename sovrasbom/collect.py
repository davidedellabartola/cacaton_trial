"""Raccolta: genera la SBOM e cerca le vulnerabilita', scegliendo il motore disponibile.

Ordine di preferenza (con --engine si puo' forzare):
  SBOM:           Syft  ->  Trivy  ->  motore integrato (solo repository di codice)
  Vulnerabilita': Grype ->  Trivy  ->  OSV.dev (servizio online, nessuna installazione)

Perche' piu' motori: il tool deve funzionare sul PC di chiunque nel team. Ogni
comando eseguito e ogni versione degli strumenti finisce nelle evidenze, cosi' chi
legge il report sa esattamente con che cosa e' stato prodotto e puo' rifarlo.
"""

import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import builtin_sbom


class ToolMissing(RuntimeError):
    pass


def find_tool(name: str) -> str:
    """Percorso dello strumento: prima il PATH, poi le cartelle dove di solito si installa a mano.

    Perche': su Windows capita spesso che il PATH del terminale non sia aggiornato
    (es. Git Bash aperto prima di modificarlo). Cerchiamo anche in:
    SOVRASBOM_TOOLS (elenco di cartelle), ~/tools/<nome>, ~/tools, ~/bin, ~/.local/bin
    """
    found = shutil.which(name)
    if found:
        return found
    home = os.path.expanduser("~")
    dirs = [d for d in os.environ.get("SOVRASBOM_TOOLS", "").split(os.pathsep) if d]
    dirs += [os.path.join(home, "tools", name), os.path.join(home, "tools"),
             os.path.join(home, "bin"), os.path.join(home, ".local", "bin")]
    for d in dirs:
        for candidate in (name, name + ".exe"):
            path = os.path.join(d, candidate)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
    return ""


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _why(res) -> str:
    """Ultima riga utile dell'errore di uno strumento esterno (i messaggi completi sono lunghi)."""
    lines = [l.strip() for l in (res.stderr or res.stdout or "").splitlines() if l.strip()]
    msg = lines[-1] if lines else f"codice di uscita {res.returncode}"
    return msg if len(msg) <= 160 else msg[:157] + "..."


def _run(cmd: list, log: list, timeout=3600) -> subprocess.CompletedProcess:
    log.append(" ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ============================================================ versioni strumenti
def tool_version(tool: str) -> str:
    """Versione dello strumento, da riportare nelle evidenze (riproducibilita')."""
    exe = find_tool(tool)
    if not exe:
        return "non installato"
    # attenzione: per Trivy l'opzione e' -f json (con -o scriverebbe un file chiamato "json")
    cmd = [exe, "version", "-f", "json"] if tool == "trivy" else [exe, "version", "-o", "json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        data = json.loads(out.stdout)
        return data.get("version") or data.get("Version") or "?"
    except Exception:
        return "?"


def vuln_db_info(engine: str) -> str:
    """Data del database: un risultato 'nessuna vulnerabilita'' vale solo se il database e' recente."""
    try:
        if engine == "grype":
            out = subprocess.run([find_tool("grype"), "db", "status", "-o", "json"], capture_output=True, text=True, timeout=60)
            data = json.loads(out.stdout)
            return data.get("built") or data.get("Built") or "?"
        if engine == "trivy":
            out = subprocess.run([find_tool("trivy"), "version", "-f", "json"], capture_output=True, text=True, timeout=60)
            return (json.loads(out.stdout).get("VulnerabilityDB") or {}).get("UpdatedAt") or "?"
        if engine == "osv":
            return "OSV.dev interrogato il " + datetime.now(timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        pass
    return "n/d"


# ============================================================ SBOM
def _trivy_sbom_cmd(source: str, out_path: str):
    scheme, _, value = source.partition(":")
    base = [find_tool("trivy"), "--quiet"]
    tail = ["--format", "cyclonedx", "--output", out_path]
    if scheme in ("dir", "file"):
        return base + ["fs"] + tail + [value]
    if scheme in ("docker", "podman", "registry"):
        return base + ["image"] + tail + [value]
    if scheme in ("docker-archive", "oci-archive"):
        return base + ["image"] + tail + ["--input", value]
    return None


def generate_sbom(target, out_path: str, log: list, engine: str = "auto") -> str:
    """Genera una SBOM CycloneDX e restituisce il nome del motore usato."""
    order = ["syft", "trivy", "integrato"] if engine == "auto" else [engine]
    errors = []
    for eng in order:
        if eng in ("syft", "trivy") and not find_tool(eng):
            errors.append(f"{eng} non installato")
            continue
        if eng == "syft":
            res = _run([find_tool("syft"), target.scan_source, "-o", f"cyclonedx-json={out_path}", "-q"], log)
        elif eng == "trivy":
            cmd = _trivy_sbom_cmd(target.scan_source, out_path)
            if not cmd:
                errors.append(f"trivy non supporta la sorgente {target.scan_source}")
                continue
            res = _run(cmd, log)
        else:
            if not target.files_root:
                errors.append("il motore integrato legge solo cartelle, archivi e repository")
                continue
            log.append(f"motore integrato: lettura dei file di dipendenze in {target.files_root}")
            builtin_sbom.generate(target.files_root, target.name, out_path)
            return "integrato"
        if res.returncode == 0:
            return eng
        errors.append(f"{eng}: {_why(res)}")
    raise ToolMissing("impossibile generare la SBOM (" + "; ".join(errors) +
                      "). Installa Syft o Trivy, oppure passa una SBOM gia' pronta.")


# ============================================================ vulnerabilita'
def scan_vulnerabilities(sbom_path: str, out_path: str, log: list, engine: str = "auto",
                         offline: bool = False) -> str:
    """Cerca le vulnerabilita' dei componenti della SBOM; restituisce il motore usato."""
    order = ["grype", "trivy", "osv"] if engine == "auto" else [engine]
    errors = []
    for eng in order:
        if eng == "osv":
            if offline:
                errors.append("OSV.dev richiede la rete (--offline attivo)")
                continue
            log.append(f"interrogazione OSV.dev (api.osv.dev) per i purl della SBOM {sbom_path}")
            try:
                query_osv(sbom_path, out_path)
                return "osv"
            except Exception as exc:
                errors.append(f"osv: servizio non raggiungibile ({str(exc)[:80]})")
                continue
        if not find_tool(eng):
            errors.append(f"{eng} non installato")
            continue
        if eng == "grype":
            res = _run([find_tool("grype"), f"sbom:{sbom_path}", "-o", "json", "--file", out_path, "-q"], log)
        else:
            res = _run([find_tool("trivy"), "--quiet", "sbom", "--format", "json", "--output", out_path, sbom_path], log)
        if res.returncode == 0:
            return eng
        errors.append(f"{eng}: {_why(res)}")
    raise ToolMissing("scansione delle vulnerabilita' non eseguita:\n      - " + "\n      - ".join(errors) +
                      "\n      (con Grype: 'grype db update' scarica il database; serve la rete la prima volta)")


# ------------------------------------------------------------ OSV.dev
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
OSV_MAX_DETAILS = 400


def _post_json(url, payload, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "sovrasbom"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _get_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "sovrasbom"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def query_osv(sbom_path: str, out_path: str):
    """Chiede a OSV.dev le vulnerabilita' di ogni componente (per purl) e salva le risposte grezze.

    Le risposte grezze vanno nelle evidenze: chiunque puo' vedere che cosa ha detto il servizio.
    """
    from .sbom import load_sbom
    comps = [c for c in load_sbom(sbom_path).components if c.purl and c.version and "@" in c.purl]
    queries = [{"package": {"purl": c.purl.split("?")[0]}} for c in comps]
    results = []
    for i in range(0, len(queries), 1000):
        results += _post_json(OSV_BATCH, {"queries": queries[i:i + 1000]}).get("results", [])
    ids = sorted({v["id"] for r in results for v in (r.get("vulns") or [])})[:OSV_MAX_DETAILS]
    with ThreadPoolExecutor(8) as ex:
        details = dict(zip(ids, ex.map(lambda i: _safe_get(OSV_VULN + i), ids)))
    matches = []
    for comp, res in zip(comps, results):
        for v in res.get("vulns") or []:
            matches.append({"component": comp.name, "version": comp.version, "purl": comp.purl,
                            "ecosystem": comp.ecosystem, "id": v["id"], "detail": details.get(v["id"])})
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"engine": "osv", "matches": matches, "queried": len(queries)}, fh, indent=1)


def _safe_get(url):
    try:
        return _get_json(url)
    except Exception:
        return None
