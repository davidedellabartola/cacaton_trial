"""Licenze: classifica ogni componente per grado di apertura e controlla la compatibilita'.

Perche' conta per la sovranita': la licenza decide se la PA (o un fornitore
alternativo) puo' studiare, modificare, ricompilare e mantenere il componente
anche se il fornitore originale sparisce o cambia condizioni. Il CAD (artt. 68-69)
chiede alla PA di valutare proprio questo aspetto.

La tabella di compatibilita' (compatibility) e' volutamente SEMPLIFICATA, ripresa da
sovereignty_check.py: segnala i casi noti piu' frequenti, non e' consulenza legale.
"""

import re
from collections import Counter

PERMISSIVE = ("MIT", "EXPAT", "BSD", "0BSD", "APACHE", "ISC", "ZLIB", "PSF", "PYTHON", "X11",
              "UNICODE", "UNLICENSE", "CC0", "BSL-1", "BOOST", "OPENSSL", "SSLEAY", "CURL",
              "POSTGRESQL", "WTFPL", "PUBLIC-DOMAIN", "PUBLICDOMAIN", "ARTISTIC", "W3C",
              "BITSTREAM", "OFL", "FTL", "LIBPNG", "IJG", "HPND", "MIT-0", "BLUEOAK", "UPL")
WEAK = ("LGPL", "MPL", "EPL", "CDDL", "CPL", "MS-PL", "OSL")
STRONG = ("GPL", "EUPL", "CECILL")
NETWORK = ("AGPL",)
PROPRIETARY = ("SSPL", "BUSL", "ELASTIC", "COMMONS-CLAUSE", "PROPRIETARY", "COMMERCIAL",
               "EULA", "CONFLUENT", "ORACLE")
# licenze con restrizioni d'uso, non approvate OSI: "JSON" (org.json) impone "Good, not Evil"
RESTRICTED = ("JSON",)
# "UNLICENSED" in npm significa "nessun permesso di riuso": il contrario di "Unlicense" (pubblico dominio)
NOT_LICENSED = ("UNLICENSED", "ALL-RIGHTS-RESERVED", "NOT-LICENSED")
# licenze approvate da OSI (prefissi degli identificativi SPDX piu' comuni)
OSI_PREFIXES = ("MIT", "APACHE-2.0", "GPL-", "LGPL-", "AGPL-", "BSD-", "MPL-2.0", "EUPL-", "ISC", "EPL-",
                "0BSD", "ZLIB", "UNLICENSE", "ARTISTIC-2.0", "BSL-1.0", "PSF-2.0", "CDDL-1.0", "OSL-3.0",
                "UPL-1.0", "MS-PL", "POSTGRESQL", "CECILL-2.1")

CATEGORIES = [
    "Permissiva", "Copyleft debole", "Copyleft forte", "Copyleft di rete",
    "Proprietaria / source-available", "Non riconosciuta", "Assente",
]
RANK = {"Permissiva": 0, "Copyleft debole": 1, "Copyleft forte": 2, "Copyleft di rete": 3,
        "Proprietaria / source-available": 4, "Non riconosciuta": 5}
OPEN_CATEGORIES = {"Permissiva", "Copyleft debole", "Copyleft forte", "Copyleft di rete"}
# pacchetti di sistema e azioni CI non sono "incorporati" nel progetto: esclusi dalla compatibilita'
NOT_LINKED_ECOSYSTEMS = {"deb", "rpm", "apk", "github-action"}


def _norm(tok: str) -> str:
    return tok.strip().strip("()").strip().upper().replace(" ", "-")


def classify_token(tok: str) -> str:
    t = _norm(tok)
    if not t:
        return "Non riconosciuta"
    if t in NOT_LICENSED:
        return "Proprietaria / source-available"
    if t.startswith("SEE-LICENSE-IN") or t.startswith("LICENSEREF-"):
        return "Non riconosciuta"   # licenza in un file o personalizzata: va letta a mano
    # l'ordine conta: AGPL e LGPL contengono "GPL"
    for prefix in NETWORK:
        if t.startswith(prefix):
            return "Copyleft di rete"
    for prefix in WEAK:
        if t.startswith(prefix):
            return "Copyleft debole"
    for prefix in PROPRIETARY:
        if prefix in t:
            return "Proprietaria / source-available"
    if t in RESTRICTED:
        return "Proprietaria / source-available"
    for prefix in STRONG:
        if t.startswith(prefix):
            return "Copyleft forte"
    for prefix in PERMISSIVE:
        if t.startswith(prefix):
            return "Permissiva"
    return "Non riconosciuta"


def _alternatives(expr: str) -> list:
    """Espressione SPDX -> alternative (OR), ognuna lista di licenze da rispettare insieme (AND).

    Le eccezioni (GPL-2.0 WITH Classpath-exception-2.0) ampliano i permessi della licenza a cui
    si applicano: si tolgono e resta la licenza, invece di trattarle come licenze a se'.
    """
    expr = re.sub(r"\s+WITH\s+[\w.\-+]+", "", expr or "", flags=re.I)
    expr = expr.replace("(", " ").replace(")", " ").strip()
    if not expr:
        return []
    return [[t.strip() for t in re.split(r"\s+AND\s+", alt, flags=re.I) if t.strip()]
            for alt in re.split(r"\s+OR\s+", expr, flags=re.I)]


def best_license(expr: str) -> tuple:
    """(licenza, categoria) che vale davvero: 'A OR B' -> la piu' aperta; 'A AND B' -> la piu' restrittiva."""
    best = None
    for alt in _alternatives(expr):
        worst = max(((t, classify_token(t)) for t in alt), key=lambda x: RANK[x[1]], default=None)
        if worst and (best is None or RANK[worst[1]] < RANK[best[1]]):
            best = worst
    return best or ("", "Non riconosciuta")


def classify_expression(expr: str) -> str:
    return best_license(expr)[1]


def classify_component(licenses: list) -> str:
    if not licenses:
        return "Assente"
    # piu' licenze dichiarate sullo stesso componente: le consideriamo tutte valide insieme
    cats = [classify_expression(l) for l in licenses]
    return max(cats, key=lambda c: RANK[c])


def is_osi(spdx: str) -> bool:
    return any(_norm(l).startswith(OSI_PREFIXES) for alt in _alternatives(spdx) for l in alt[:1])


def _compat(project: str, lid: str, cat: str):
    """Tabella SEMPLIFICATA di compatibilita' (non e' consulenza legale): (gravita', messaggio) o None."""
    if cat == "Proprietaria / source-available":
        return ("Alta", "licenza non open source o source-available: verificare i diritti di riuso")
    p, l = _norm(project), _norm(lid)
    if p in ("GPL-2.0", "GPL-2.0-ONLY"):
        if l.startswith("APACHE-2.0"):
            return ("Alta", "Apache-2.0 è incompatibile con GPL-2.0-only")
        if l.startswith(("GPL-3", "AGPL-3")):
            return ("Alta", "GPL-3.0/AGPL-3.0 sono incompatibili con GPL-2.0-only")
    if p.startswith(("GPL", "AGPL")) and l.startswith(("EPL-1.0", "CPL-1.0")):
        return ("Alta", "EPL-1.0 è incompatibile con GPL e AGPL: non si può distribuire nello stesso programma")
    if cat == "Copyleft di rete" and not p.startswith("AGPL"):
        return ("Media", "AGPL: obblighi anche per i servizi offerti via rete (rilevante per i servizi PA)")
    if cat == "Copyleft forte" and classify_token(project) == "Permissiva":
        return ("Media", "copyleft forte in un progetto con licenza permissiva: l'insieme potrebbe doverla adottare")
    if p.startswith("EUPL") and cat in ("Copyleft forte", "Copyleft debole") and not l.startswith("EUPL"):
        return ("Info", "progetto EUPL: verificare la compatibilità con le licenze dell'appendice EUPL")
    return None


def compatibility(components: list, project_license: str) -> list:
    """Problemi di compatibilita' tra le licenze dei componenti e quella del progetto."""
    issues = {}
    for c in components:
        if c.dev or c.ecosystem in NOT_LINKED_ECOSYSTEMS or not c.licenses:
            continue
        lid, cat = best_license(" AND ".join(f"({l})" for l in c.licenses))
        if cat == "Non riconosciuta":
            continue
        hit = _compat(project_license or "", lid, cat)
        if hit:
            issues.setdefault(hit, []).append(f"{c.name} ({lid})")
    order = {"Alta": 0, "Media": 1, "Info": 2}
    return [{"severity": sev, "message": msg, "components": sorted(set(who))}
            for (sev, msg), who in sorted(issues.items(), key=lambda kv: order[kv[0][0]])]


def analyze(components: list, project_license: str = "") -> dict:
    per_comp = [(c, classify_component(c.licenses)) for c in components]
    counts = Counter(cat for _, cat in per_comp)
    total = len(components) or 1
    raw = Counter(l for c in components for l in c.licenses)
    return {
        "by_category": {cat: counts.get(cat, 0) for cat in CATEGORIES},
        "open_ratio": sum(counts.get(c, 0) for c in OPEN_CATEGORIES) / total,
        "unknown_ratio": (counts.get("Non riconosciuta", 0) + counts.get("Assente", 0)) / total,
        "missing_ratio": counts.get("Assente", 0) / total,
        "from_registry": sum(1 for c in components if c.license_source == "deps.dev"),
        # elenco verificabile anche quando la SBOM allegata e' quella originale (non modificata)
        "registry_licenses": [{"name": c.name, "version": c.version, "license": " AND ".join(c.licenses)}
                              for c in components if c.license_source == "deps.dev"],
        "top_licenses": raw.most_common(10),
        "proprietary": [(c.name, c.version, ", ".join(c.licenses)) for c, cat in per_comp
                        if cat == "Proprietaria / source-available"],
        "network_copyleft": [(c.name, c.version, ", ".join(c.licenses)) for c, cat in per_comp
                             if cat == "Copyleft di rete"],
        "project_license": project_license,
        "compatibility": compatibility(components, project_license) if project_license else [],
    }
