"""Indice di sovranita': fino a sette dimensioni da 0 a 100, poi la media.

La formula e' volutamente semplice e dichiarata nella presentazione: un indice
che non si puo' spiegare non e' verificabile, e la sfida chiede strumenti che
rendano i principi "concreti e verificabili".

- Trasparenza    = punteggio di qualita' della SBOM (elementi minimi NTIA)
- Apertura       = % di componenti con licenza open source riconosciuta
                   (non misurabile se oltre l'80% dei componenti non dichiara la licenza)
- Tracciabilita' = % di componenti con identificativo univoco E origine nota
                   (namespace, fornitore dichiarato o registro ufficiale implicito nel purl)
                   E provenienza non opaca (non da git, percorsi locali o fonti alternative)
- Sicurezza      = 100 - penalita' (KEV, vulnerabilita' gravi, quota di componenti vulnerabili,
                   segnali gravi nel codice del progetto: 10 ciascuno, massimo 30)
- Manutenibilita' = 100 - penalita' per dipendenze non mantenute, deprecate o molto indietro
                   (solo online: dati di deps.dev)
- Governance     = % di segnali di buona gestione del progetto (solo per repository)
- Filiera di build = 100 - penalita' della pipeline (solo se ci sono CI o Dockerfile)
Le dimensioni non misurabili per un certo input vengono escluse dalla media, non azzerate.
Con meno di tre dimensioni misurate l'indice si calcola ma non riceve un livello ("Non classificabile").
"""

from ..model import REGISTRY_ECOSYSTEMS
from .provenance import OPAQUE_SOURCES

MIN_CLASSIFIED = 3


def _clamp(x):
    return max(0, min(100, round(x)))


def security_score(v: dict, code: dict = None) -> int:
    code_high = sum(1 for x in (code or {}).get("findings", []) if x["severity"] == "Alta")
    if v is None and not code_high:
        return -1
    score = 100
    if v is not None:
        # una grave con la funzione vulnerabile non caricata o non chiamata pesa un quarto
        un = v.get("unreached") or {}
        crit = v["by_severity"].get("Critical", 0) - 0.75 * un.get("Critical", 0)
        high = v["by_severity"].get("High", 0) - 0.75 * un.get("High", 0)
        score -= 30 if v["kev"] else 0
        score -= min(40, 4 * crit + 1 * high)
        score -= 30 * v["component_ratio"]
    # problemi gravi nel codice del progetto (crittografia debole, segreti nel browser, credenziali nell'URL)
    score -= min(30, 10 * code_high)
    return _clamp(score)


def is_traceable(c) -> bool:
    return bool((c.purl or c.cpes) and (c.namespace or c.supplier or c.ecosystem in REGISTRY_ECOSYSTEMS)
                and c.source_kind not in OPAQUE_SOURCES)


def analyze(components, quality, licenses, vulns, governance=None, pipeline=None, maintenance=None,
            code=None) -> dict:
    total = len(components) or 1
    traceable = sum(1 for c in components if is_traceable(c)) / total
    has_components = bool(components)
    dims = {
        "Trasparenza": _clamp(quality["score"]) if has_components else -1,
        # se quasi nessun componente dichiara la licenza, o le licenze non sono state cercate,
        # il dato manca: meglio "non misurabile" che un voto basso
        "Apertura": _clamp(100 * licenses["open_ratio"]) if has_components and licenses["unknown_ratio"] <= 0.8
        and not licenses.get("not_searched") else -1,
        "Tracciabilità": _clamp(100 * traceable) if has_components else -1,
        "Sicurezza": security_score(vulns if has_components else None, code),
        "Manutenibilità": (maintenance or {}).get("score", -1) if (maintenance or {}).get("applicable") else -1,
        "Governance": (governance or {}).get("score", -1) if (governance or {}).get("applicable") else -1,
        "Filiera di build": (pipeline or {}).get("score", -1) if (pipeline or {}).get("applicable") else -1,
    }
    valid = [v for v in dims.values() if v >= 0]
    index = round(sum(valid) / len(valid)) if valid else 0
    # senza le dimensioni della SBOM l'indice descrive solo il progetto, non il software: va detto
    partial = not has_components or len(valid) < 4
    # con meno di MIN_CLASSIFIED dimensioni il numero dice qualcosa su quelle, non sul software:
    # niente giudizio "Critico/Buono" in copertina
    classified = len(valid) >= MIN_CLASSIFIED
    if not classified:
        level = "Non classificabile"
    elif index >= 75:
        level = "Buono"
    elif index >= 50:
        level = "Da migliorare"
    else:
        level = "Critico"
    return {"dimensions": dims, "index": index, "level": level, "partial": partial, "classified": classified,
            "measured": len(valid), "possible": len(dims)}
