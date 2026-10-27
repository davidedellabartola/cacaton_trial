"""Analizzatori: ognuno guarda il software da un punto di vista diverso.

run_all() li esegue in ordine e restituisce un unico dizionario di risultati
("findings") che il generatore della presentazione legge.
I primi lavorano sulla SBOM; governance e pipeline leggono i file del repository
(solo se l'input e' un repository, una cartella di sorgenti o un archivio).
La licenza del progetto letta dalla governance serve poi al controllo di
compatibilita' delle licenze dei componenti.
"""

from . import (code, composition, duplicates, governance, licenses, maintenance, pipeline, provenance, quality,
               reach, recommendations, sovereignty, vendor_diff)
from . import vulns as vulns_mod


def run_all(sbom, vulnerabilities=None, vendor_sbom=None, target=None, online=True, context=None) -> dict:
    """context: informazioni sull'analisi che servono alle raccomandazioni (motore, rete, deps.dev)."""
    comps = sbom.components
    context = dict(context or {})
    root = target.root if target is not None else ""
    # prima dell'ordine di intervento: le gravi nelle librerie copiate ma non caricate scendono in fondo
    usage = reach.analyze(vulnerabilities, comps, root, code.own_files(root)) if vulnerabilities and root else {}
    findings = {
        "composition": composition.analyze(comps),
        "quality": quality.analyze(sbom),
        "duplicates": duplicates.analyze(comps),
        "vulns": vulns_mod.analyze(vulnerabilities, comps) if vulnerabilities is not None else None,
        "vendor_diff": vendor_diff.analyze(vendor_sbom, sbom) if vendor_sbom is not None else None,
        "maintenance": maintenance.analyze(comps, context.get("depsdev")),
        "governance": {"applicable": False},
        "pipeline": {"applicable": False},
        "code": {"applicable": False},
        "copied_usage": usage,
    }
    if target is not None and target.root:
        findings["governance"] = governance.analyze(target.root, target.git, target.kind, online)
        if findings["governance"]["applicable"]:
            findings["pipeline"] = pipeline.analyze(target.root, online)
            rel = (target.extra or {}).get("release") or {}
            if rel.get("signatures"):
                # le firme possono essere prodotte fuori dalla pipeline: contano se sono nel rilascio
                findings["pipeline"]["has_signing"] = True
            findings["pipeline"]["score"] = pipeline.score(findings["pipeline"])
            findings["code"] = code.analyze(target.root)
    findings["licenses"] = licenses.analyze(comps, findings["governance"].get("license", ""))
    # licenze mancanti perche' nessuno le ha cercate (motore integrato, senza deps.dev): e' un limite
    # dell'analisi, non del software, quindi l'Apertura diventa "non misurabile" invece di un voto basso
    findings["licenses"]["not_searched"] = (context.get("sbom_engine") == "integrato" and not context.get("depsdev")
                                            and findings["licenses"]["missing_ratio"] > 0.2)
    findings["provenance"] = provenance.analyze(comps, sbom.notes, target.root if target is not None else "")
    findings["sovereignty"] = sovereignty.analyze(comps, findings["quality"], findings["licenses"],
                                                  findings["vulns"], findings["governance"], findings["pipeline"],
                                                  findings["maintenance"], findings["code"])
    findings["release"] = (target.extra or {}).get("release") if target is not None else None
    findings["context"] = context
    findings["recommendations"] = recommendations.build(findings)
    return findings
