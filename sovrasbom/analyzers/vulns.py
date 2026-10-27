"""Vulnerabilita': lettura dei risultati (Grype, Trivy o OSV.dev), arricchimento KEV/EPSS, riepilogo.

Perche' arricchire: una lista di centinaia di CVE non aiuta a decidere.
- CISA KEV: catalogo delle vulnerabilita' che risultano GIA' sfruttate in attacchi reali.
- EPSS (FIRST.org): probabilita' stimata che una CVE venga sfruttata nei prossimi 30 giorni.
Insieme alla gravita' (CVSS) permettono di dire alla PA cosa correggere PRIMA.
"""

import json
import math
import urllib.request
from collections import Counter, defaultdict

from ..model import SEVERITY_ORDER, Vulnerability

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve="


def _norm_sev(s: str) -> str:
    s = (s or "Unknown").capitalize()
    s = {"Moderate": "Medium", "Important": "High", "None": "Negligible"}.get(s, s)
    return s if s in SEVERITY_ORDER else "Unknown"


def load_results(path: str) -> tuple:
    """Riconosce il formato dal contenuto e restituisce (vulnerabilita', motore)."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if doc.get("engine") == "osv":
        return load_osv(doc), "osv"
    if "Results" in doc or "SchemaVersion" in doc:
        return load_trivy(doc), "trivy"
    return load_grype(path), "grype"


def load_trivy(doc: dict) -> list:
    seen = {}
    for res in doc.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
            if key in seen:
                continue
            cvss = 0.0
            for src in (v.get("CVSS") or {}).values():
                cvss = max(cvss, float(src.get("V3Score") or src.get("V40Score") or 0))
            fixed = [f.strip() for f in (v.get("FixedVersion") or "").split(",") if f.strip()]
            status = v.get("Status") or ("fixed" if fixed else "unknown")
            seen[key] = Vulnerability(
                id=v.get("VulnerabilityID", "?"), severity=_norm_sev(v.get("Severity")),
                component=v.get("PkgName", "?"), version=v.get("InstalledVersion", ""),
                ecosystem=res.get("Type", ""), fixed_in=fixed,
                fix_state="fixed" if fixed else ("wont-fix" if status == "will_not_fix" else "not-fixed"),
                cvss=cvss, aliases=[a for a in (v.get("VendorIDs") or []) if a],
                description=(v.get("Title") or v.get("Description") or "")[:300],
            )
    return list(seen.values())


# ------------------------------------------------------------------ CVSS v3 e v4
# OSV.dev fornisce il vettore CVSS (es. "CVSS:3.1/AV:N/AC:L/...") ma non il punteggio:
# per la v3 lo calcoliamo con la formula ufficiale FIRST della specifica CVSS v3.1.
_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
      "A": {"H": 0.56, "L": 0.22, "N": 0}}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float:
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))
    except (KeyError, ValueError, IndexError):
        return 0.0


def cvss4_score(vector: str) -> float:
    """CVSS v4.0: la formula usa una tabella di 270 "macrovettori" della specifica FIRST.

    Invece di ricopiarla a mano (facile sbagliare un valore) usiamo la libreria `cvss`
    (RedHat, pip install cvss), che la implementa ed e' verificata sugli esempi ufficiali.
    Senza la libreria restituisce 0: la gravita' viene allora presa dall'etichetta dell'advisory.
    """
    try:
        from cvss import CVSS4
    except ImportError:
        return 0.0
    try:
        return float(CVSS4(vector).base_score)
    except Exception:
        return 0.0


def osv_missing_details(path: str) -> tuple:
    """(advisory senza dettagli, advisory totali): OSV.dev viene interrogato per al massimo
    OSV_MAX_DETAILS advisory; per le altre mancano gravita' e correzione (vanno dichiarate)."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return 0, 0
    ids = {m["id"] for m in doc.get("matches") or []}
    missing = {m["id"] for m in doc.get("matches") or [] if not m.get("detail")}
    return len(missing), len(ids)


def _sev_from_score(score: float) -> str:
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else \
        "Low" if score > 0 else "Unknown"


def load_osv(doc: dict) -> list:
    seen = {}
    for m in doc.get("matches") or []:
        det = m.get("detail") or {}
        key = (m["id"], m["component"], m["version"])
        if key in seen:
            continue
        cvss = 0.0
        for s in det.get("severity") or []:
            stype = str(s.get("type", ""))
            if stype.startswith("CVSS_V3"):
                cvss = max(cvss, cvss3_score(s.get("score", "")))
            elif stype.startswith("CVSS_V4"):
                cvss = max(cvss, cvss4_score(s.get("score", "")))
        label = (det.get("database_specific") or {}).get("severity")
        sev = _norm_sev(label) if label else _sev_from_score(cvss)
        fixed = []
        for aff in det.get("affected") or []:
            for rng in aff.get("ranges") or []:
                fixed += [e["fixed"] for e in rng.get("events") or [] if e.get("fixed")]
        seen[key] = Vulnerability(
            id=m["id"], severity=sev, component=m["component"], version=m["version"],
            ecosystem=m.get("ecosystem", ""), fixed_in=sorted(set(fixed)),
            fix_state="fixed" if fixed else "unknown", cvss=cvss,
            aliases=det.get("aliases") or [], description=(det.get("summary") or "")[:300],
            details=(det.get("details") or "")[:6000],
        )
    return list(seen.values())


def load_grype(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    seen = {}
    for m in doc.get("matches", []) or []:
        v = m.get("vulnerability", {}) or {}
        a = m.get("artifact", {}) or {}
        key = (v.get("id"), a.get("name"), a.get("version"))
        if key in seen:
            continue  # stessa CVE sullo stesso componente trovato in piu' percorsi
        cvss = 0.0
        for c in (v.get("cvss") or []):
            cvss = max(cvss, float((c.get("metrics") or {}).get("baseScore") or 0))
        related = m.get("relatedVulnerabilities") or []
        for r in related:
            for c in (r.get("cvss") or []):
                cvss = max(cvss, float((c.get("metrics") or {}).get("baseScore") or 0))
        epss = -1.0
        for e in (v.get("epss") or []):          # presente nelle versioni recenti di Grype
            epss = max(epss, float(e.get("epss") or 0))
        kev = bool(v.get("knownExploited"))       # idem
        fix = v.get("fix") or {}
        seen[key] = Vulnerability(
            id=v.get("id", "?"),
            severity=_norm_sev(v.get("severity")),
            component=a.get("name", "?"),
            version=a.get("version", ""),
            ecosystem=a.get("type", ""),
            fixed_in=list(fix.get("versions") or []),
            fix_state=fix.get("state", "unknown") or "unknown",
            cvss=cvss,
            epss=epss,
            kev=kev,
            aliases=[r.get("id") for r in related if r.get("id")],
            description=(v.get("description") or (related[0].get("description") if related else "") or "")[:300],
        )
    return list(seen.values())


def _fetch_json(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": "sovrasbom"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def enrich(vulns: list, warnings: list) -> dict:
    """Aggiunge KEV ed EPSS se Grype non li ha gia' forniti. Richiede accesso a Internet."""
    info = {"kev": "non consultato", "epss": "non consultato"}
    cves = sorted({c for v in vulns for c in v.cve_ids})
    if not cves:
        return info
    # --- KEV
    try:
        kev_doc = _fetch_json(KEV_URL)
        kev_ids = {x.get("cveID") for x in kev_doc.get("vulnerabilities", [])}
        for v in vulns:
            if any(c in kev_ids for c in v.cve_ids):
                v.kev = True
        info["kev"] = f"catalogo CISA KEV, versione {kev_doc.get('catalogVersion', '?')}"
    except Exception as exc:
        warnings.append(f"Catalogo KEV non raggiungibile ({exc}): uso solo i dati di Grype")
    # --- EPSS (a blocchi, per non superare la lunghezza massima dell'URL)
    try:
        scores = {}
        for i in range(0, len(cves), 80):
            data = _fetch_json(EPSS_URL + ",".join(cves[i:i + 80]))
            for row in data.get("data", []):
                scores[row["cve"]] = float(row.get("epss") or 0)
        for v in vulns:
            for c in v.cve_ids:
                if c in scores:
                    v.epss = max(v.epss, scores[c])
        info["epss"] = "API FIRST.org EPSS"
    except Exception as exc:
        warnings.append(f"API EPSS non raggiungibile ({exc}): uso solo i dati di Grype")
    return info


def priority_score(v: Vulnerability) -> float:
    """Ordine di intervento: prima le sfruttate (KEV), poi probabilita' x impatto.

    Stesso principio rischio = probabilita' x impatto: la gravita' CVSS misura
    l'impatto, EPSS la probabilita'. Una correzione disponibile alza la priorita'
    perche' l'intervento e' immediatamente possibile.
    """
    sev_weight = {"Critical": 10, "High": 7.5, "Medium": 5, "Low": 2.5, "Negligible": 1, "Unknown": 3}
    impact = v.cvss if v.cvss > 0 else sev_weight[v.severity]
    prob = v.epss if v.epss >= 0 else 0.05
    score = impact * (0.3 + prob)
    if v.kev:
        score += 100
    if v.fix_state == "fixed":
        score *= 1.2
    if v.reach:                      # funzione vulnerabile non caricata o non chiamata dal progetto
        score *= 0.3
    return score


def analyze(vulns: list, components: list) -> dict:
    by_sev = Counter(v.severity for v in vulns)
    by_component = defaultdict(list)
    for v in vulns:
        by_component[(v.component, v.version)].append(v)
    top_components = sorted(
        by_component.items(),
        key=lambda kv: (
            -any(v.kev for v in kv[1]),
            -sum(1 for v in kv[1] if v.severity in ("Critical", "High")),
            -len(kv[1]),
        ),
    )
    return {
        "total": len(vulns),
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITY_ORDER},
        "fixable": sum(1 for v in vulns if v.fix_state == "fixed"),
        "fixable_crit_high": sum(1 for v in vulns if v.fix_state == "fixed" and v.severity in ("Critical", "High")
                                 and not v.reach),
        # gravi ma con la funzione vulnerabile non caricata o non chiamata dal progetto (librerie copiate)
        "unreached": {s: sum(1 for v in vulns if v.reach and v.severity == s) for s in ("Critical", "High")},
        "reach_notes": {v.id: f"{v.reach}: {v.reach_note}" for v in vulns if v.reach},
        "kev": sorted({v.id for v in vulns if v.kev}),
        "epss_high": sum(1 for v in vulns if v.epss >= 0.1),
        "vulnerable_components": len(by_component),
        "component_ratio": (len(by_component) / len(components)) if components else 0.0,
        "prioritized": sorted(vulns, key=priority_score, reverse=True),
        "top_components": [
            {
                "name": name, "version": ver, "total": len(vs),
                "crit_high": sum(1 for v in vs if v.severity in ("Critical", "High")),
                "fixable": sum(1 for v in vs if v.fix_state == "fixed"),
                "kev": any(v.kev for v in vs),
            }
            for (name, ver), vs in top_components
        ],
    }
