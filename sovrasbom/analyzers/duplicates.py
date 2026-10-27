"""Componenti presenti in piu' versioni nello stesso software.

Perche': e' il caso Zimbra. Il prodotto porta con se' copie proprie di librerie
(OpenSSL, Java...) accanto a quelle del sistema operativo. Ogni copia va
aggiornata separatamente: se il fornitore e' lento, l'aggiornamento del sistema
operativo NON basta e la PA crede di essere protetta senza esserlo.
"""

from collections import defaultdict


def analyze(components: list) -> dict:
    groups = defaultdict(list)
    for c in components:
        if c.name:
            groups[c.name.lower()].append(c)
    multi = []
    for name, comps in groups.items():
        versions = sorted({c.version for c in comps if c.version})
        if len(versions) > 1:
            locs = []
            for c in comps:
                locs.extend(c.locations[:1])
            multi.append({
                "name": comps[0].name,
                "versions": versions,
                "ecosystems": sorted({c.ecosystem for c in comps}),
                "copies": len(comps),
                "locations": sorted(set(locs))[:3],
            })
    multi.sort(key=lambda m: (-len(m["versions"]), m["name"]))
    return {"multi_version": multi, "count": len(multi)}
