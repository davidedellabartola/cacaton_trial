"""Manutenibilita' delle dipendenze: i componenti sono ancora mantenuti da qualcuno?

Usa i dati di deps.dev (modulo depsdev, solo online). Una dipendenza senza release da
oltre 18 mesi, deprecata o rimasta indietro di due o piu' versioni maggiori e' un
debito: quando arrivera' una vulnerabilita', la correzione potrebbe non esserci o
richiedere un aggiornamento difficile. Per la PA significa costi futuri e dipendenza
da chi saprà fare quell'aggiornamento.

Punteggio (dimensione "Manutenibilità" dell'indice, solo se almeno una dipendenza e' stata valutata):
  100 - 200 x quota (non mantenute o deprecate) - 50 x quota (indietro di 2+ versioni maggiori)
"""

import re

STALE_DAYS = 548   # circa 18 mesi


def _major(v):
    m = re.search(r"\d+", v or "")
    return int(m.group()) if m else None


def analyze(components: list, net_info: dict = None) -> dict:
    evaluated = [c for c in components if c.registry.get("net") == "ok"]
    if not evaluated:
        return {"applicable": False, "net": net_info}
    stale = [c for c in evaluated if (c.registry.get("latest_days") or 0) > STALE_DAYS]
    deprecated = [c for c in evaluated if c.registry.get("deprecated")]
    behind = [c for c in evaluated
              if None not in (_major(c.registry.get("latest")), _major(c.version))
              and _major(c.registry["latest"]) - _major(c.version) >= 2]
    vulnerable = [c for c in evaluated if c.registry.get("advisories")]
    n = len(evaluated)
    bad = {id(c) for c in stale + deprecated}
    score = max(0, round(100 - 200 * len(bad) / n - 50 * len(behind) / n))
    row = lambda c: {"name": c.name, "version": c.version, "latest": c.registry.get("latest"),
                     "days": c.registry.get("latest_days")}
    return {
        "applicable": True,
        "net": net_info,
        "evaluated": n,
        "stale": [row(c) for c in sorted(stale, key=lambda c: -(c.registry.get("latest_days") or 0))],
        "deprecated": [row(c) for c in deprecated],
        "behind": [row(c) for c in behind],
        "vulnerable": [{"name": c.name, "version": c.version, "advisories": c.registry["advisories"]}
                       for c in vulnerable],
        "score": score,
    }
