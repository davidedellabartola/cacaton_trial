"""Composizione e provenienza: di cosa e' fatto il software e da dove arrivano i pezzi.

L'ecosistema (deb, java, npm, binario...) dice con quale meccanismo un componente
viene aggiornato. Il namespace/fornitore dice CHI lo distribuisce: e' il primo
indizio sulla catena di fornitura (es. pacchetti "ubuntu" vs pacchetti del vendor).
I componenti "binari" senza metadati sono la zona piu' opaca: nessun gestore di
pacchetti li aggiorna e spesso non hanno versione affidabile.
"""

from collections import Counter

from ..model import REGISTRY_ECOSYSTEMS


def analyze(components: list) -> dict:
    eco = Counter(c.ecosystem for c in components)
    origins = Counter()
    for c in components:
        origin = c.namespace or c.supplier or (f"registro {c.ecosystem}" if c.ecosystem in REGISTRY_ECOSYSTEMS
                                                else "non identificata")
        origins[origin[:40]] += 1
    no_version = sum(1 for c in components if not c.version)
    opaque = sum(1 for c in components if c.ecosystem in ("binario", "sconosciuto"))
    return {
        "total": len(components),
        "by_ecosystem": eco.most_common(),
        "top_origins": origins.most_common(8),
        "no_version": no_version,
        "opaque": opaque,
    }
