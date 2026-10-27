"""Evidenze verificabili: chi, cosa, quando, con quali strumenti, con quale risultato.

Perche': la sfida chiede principi "verificabili". Un report che dice "il software
ha 12 vulnerabilita'" non vale nulla se nessuno puo' controllarlo. Per questo il
tool salva insieme al report:
- gli input esatti (SBOM, risultati Grype) e i comandi eseguiti
- le versioni degli strumenti e la data del database vulnerabilita'
- l'impronta SHA-256 di ogni file (SHA256SUMS)
- opzionalmente una firma GPG di SHA256SUMS (chi ha prodotto il report)
Chiunque puo' rifare l'analisi e verificare che i file non siano stati alterati.
"""

import dataclasses
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone

from .collect import sha256_file


def _default(o):
    if dataclasses.is_dataclass(o):
        return dataclasses.asdict(o)
    if isinstance(o, set):
        return sorted(o)
    return str(o)


def write_findings(findings: dict, path: str) -> str:
    slim = dict(findings)
    if slim.get("vulns"):
        slim["vulns"] = dict(slim["vulns"])
        slim["vulns"]["prioritized"] = slim["vulns"]["prioritized"][:100]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(slim, fh, ensure_ascii=False, indent=2, default=_default)
    return path


def write_evidence(meta: dict, files: list, out_dir: str, sign_key: str = "") -> dict:
    meta = dict(meta)
    meta["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta["files"] = {os.path.basename(f): sha256_file(f) for f in files if f and os.path.exists(f)}
    ev_path = os.path.join(out_dir, "evidenze.json")
    with open(ev_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)

    sums_path = os.path.join(out_dir, "SHA256SUMS")
    with open(sums_path, "w", encoding="utf-8") as fh:
        for f in files + [ev_path]:
            if f and os.path.exists(f):
                fh.write(f"{sha256_file(f)}  {os.path.basename(f)}\n")

    signature = ""
    if sign_key:
        if shutil.which("gpg"):
            res = subprocess.run(["gpg", "--batch", "--yes", "--local-user", sign_key,
                                  "--armor", "--detach-sign", sums_path], capture_output=True, text=True)
            if res.returncode == 0:
                signature = sums_path + ".asc"
            else:
                meta.setdefault("warnings", []).append(f"Firma GPG non riuscita: {res.stderr.strip()}")
        else:
            meta.setdefault("warnings", []).append("gpg non installato: report non firmato")
    return {"evidence": ev_path, "sums": sums_path, "signature": signature, "meta": meta}
