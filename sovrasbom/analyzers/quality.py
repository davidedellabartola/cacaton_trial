"""Qualita' della SBOM rispetto agli "elementi minimi" (NTIA, ripresi da CISA e dal CRA).

Perche' prima di tutto: una SBOM incompleta da' una falsa sicurezza. Se il 40%
dei componenti non ha una versione, la scansione delle vulnerabilita' non puo'
trovarne i difetti. Misurare la qualita' dice quanto ci si puo' fidare del resto.
"""


FIELDS = [
    ("supplier", "Fornitore"),
    ("name", "Nome"),
    ("version", "Versione"),
    ("unique_id", "Identificativo univoco (purl/CPE)"),
    ("license", "Licenza"),
    ("hash", "Impronta crittografica (hash)"),
]


def _has(c, field):
    if field == "supplier":
        return bool(c.supplier or c.namespace)
    if field == "name":
        return bool(c.name)
    if field == "version":
        return bool(c.version)
    if field == "unique_id":
        return bool(c.purl or c.cpes)
    if field == "license":
        return bool(c.licenses)
    if field == "hash":
        return bool(c.hashes)
    return False


def analyze(sbom) -> dict:
    comps = sbom.components
    total = len(comps) or 1
    coverage = {label: sum(1 for c in comps if _has(c, f)) / total for f, label in FIELDS}
    document = {
        "Autore / strumento di generazione": bool(sbom.author_tools),
        "Data di generazione": bool(sbom.timestamp),
        "Relazioni di dipendenza": bool(sbom.has_dependencies),
    }
    # Punteggio: i 4 elementi minimi NTIA a livello di componente pesano l'80%,
    # gli elementi a livello di documento il 20%. Licenza e hash sono mostrati ma
    # non entrano nel punteggio perche' non fanno parte del minimo NTIA.
    ntia_fields = ["Fornitore", "Nome", "Versione", "Identificativo univoco (purl/CPE)"]
    comp_score = sum(coverage[f] for f in ntia_fields) / len(ntia_fields)
    doc_score = sum(document.values()) / len(document)
    score = round(100 * (0.8 * comp_score + 0.2 * doc_score))
    return {"coverage": coverage, "document": document, "score": score}
