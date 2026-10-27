"""Confronto tra SBOM dichiarata dal fornitore e SBOM rilevata dal tool.

Perche' e' il cuore della domanda "quanto conosce davvero la PA?": il fornitore
consegna un inventario; noi ne generiamo uno indipendente dal software
installato. Le differenze sono domande precise da porre al fornitore:
- componenti presenti ma NON dichiarati  -> l'inventario e' incompleto
- componenti dichiarati ma NON trovati   -> inventario vecchio o generico
- versioni diverse                       -> la SBOM non corrisponde a cio' che gira
"""


def _index(components):
    idx, names = {}, {}
    for c in components:
        idx.setdefault(c.name.lower(), set()).add(c.version or "")
        names.setdefault(c.name.lower(), c.name)
    return idx, names


def analyze(declared_sbom, observed_sbom) -> dict:
    dec, dec_names = _index(declared_sbom.components)
    obs, obs_names = _index(observed_sbom.components)
    undeclared = sorted(obs_names[n] for n in obs if n not in dec)
    not_found = sorted(dec_names[n] for n in dec if n not in obs)
    mismatched = []
    for n in sorted(set(dec) & set(obs)):
        dv, ov = dec[n] - {""}, obs[n] - {""}
        if dv and ov and not (dv & ov):
            mismatched.append((obs_names[n], ", ".join(sorted(dv)), ", ".join(sorted(ov))))
    coverage = (len(set(dec) & set(obs)) / len(obs)) if obs else 0.0
    return {
        "declared": len(dec),
        "observed": len(obs),
        "undeclared": undeclared,
        "not_found": not_found,
        "mismatched": mismatched,
        "coverage": coverage,
        "vendor_fmt": declared_sbom.fmt,
    }
