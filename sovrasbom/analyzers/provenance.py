"""Provenienza opaca: componenti che non arrivano da un registro pubblico verificabile.

Ripreso da sovereignty_check.py. Segnali:
- dipendenze da git, URL, percorsi locali o registri alternativi (sovrasbom:source nella SBOM)
- indici pip alternativi (--extra-index-url) e replace di Go verso altri moduli (spesso fork)
- voci di lockfile senza hash di integrita': il contenuto scaricato non e' verificato
- codice copiato nel repository (vendor/, third_party/, lib/<nome versione>, file .min.js e -min.js)
- online (deps.dev): pacchetti non trovati nel registro pubblico (indizio di dependency
  confusion), pacchetti senza repository sorgente collegato, attestazioni SLSA
I segnali "provenienza" della SBOM esistono solo se l'ha generata il motore integrato:
Syft e Trivy non li riportano, e in quel caso la sezione lo dice.
"""

from ..builtin_sbom import list_files, vendored_dirs

OPAQUE_SOURCES = {"git": "repository git", "locale": "percorso locale", "altra fonte": "URL o registro alternativo",
                  "copiato": "codice copiato nel repository"}


def analyze(components: list, notes: dict = None, root: str = "") -> dict:
    notes = notes or {}
    flags = []
    # il codice copiato ha un segnale suo, piu' sotto
    non_official = [c for c in components if c.source_kind in OPAQUE_SOURCES and c.source_kind != "copiato"]
    if non_official:
        flags.append(("Alta" if any(c.source_kind == "altra fonte" for c in non_official) else "Media",
                      "Dipendenze da fonti non ufficiali",
                      [f"{c.name} ({OPAQUE_SOURCES[c.source_kind]})" for c in non_official]))
    if notes.get("index_urls"):
        flags.append(("Alta", "Indici dei pacchetti alternativi (rischio dependency confusion)", notes["index_urls"]))
    if notes.get("replaces"):
        flags.append(("Media", "Moduli Go sostituiti (replace): spesso fork del progetto originale", notes["replaces"]))
    hashable = [c for c in components if c.hashable]
    no_hash = [c for c in hashable if not c.hashes]
    if hashable and len(no_hash) / len(hashable) >= 0.2:
        flags.append(("Media", f"Voci del lockfile senza hash di integrità ({len(no_hash)} su {len(hashable)})",
                      [c.name for c in no_hash]))
    copied = [c for c in components if c.source_kind == "copiato"]
    vendored, minjs = [], 0
    if root:
        paths = list_files(root)
        # le cartelle gia' riconosciute come componente compaiono una volta sola, con nome e versione
        locs = [loc for c in copied for loc in c.locations]
        all_vendored = sorted(vendored_dirs(paths))
        vendored = [d for d in all_vendored if not any(loc == d or loc.startswith(d + "/") for loc in locs)]
        # i .min.js dentro le cartelle gia' segnalate non si contano due volte
        inside = tuple(d + "/" for d in all_vendored)
        minjs = sum(1 for p in paths if p.endswith((".min.js", "-min.js")) and not p.startswith(inside)
                    and p not in locs)
    if copied or vendored or minjs >= 3:
        flags.append(("Media", "Codice di terzi copiato nel repository (non si aggiorna da solo)",
                      [f"{c.name} {c.version or ''}".strip() for c in copied] + vendored
                      + ([f"{minjs} file .min.js"] if minjs >= 3 else [])))
    not_found = [c for c in components if c.registry.get("net") == "non trovato"]
    if not_found:
        flags.append(("Alta", "Non trovate nel registro pubblico (possibile dependency confusion)",
                      [c.name for c in not_found]))
    evaluated = [c for c in components if c.registry.get("net") == "ok"]
    no_source = [c for c in evaluated if c.registry.get("has_source") is False]
    if evaluated and len(no_source) / len(evaluated) >= 0.2:
        flags.append(("Media", "Senza repository sorgente collegato nel registro", [c.name for c in no_source]))
    # pacchetti .zip dentro i sorgenti: e' spesso cio' che si installa davvero
    nested = [dict(zip(("archive", "status", "detail"), (n.split(";", 2) + ["", ""])[:3]))
              for n in notes.get("nested") or []]
    differ = [n for n in nested if n["status"] == "diverso"]
    if differ:
        flags.append(("Alta", "Pacchetto da installare diverso dai sorgenti",
                      [f"{n['archive']}: {n['detail']}" for n in differ]))
    unmatched = [n for n in nested if n["status"] == "non confrontabile"]
    if unmatched:
        flags.append(("Media", "Pacchetto da installare senza sorgenti corrispondenti (analizzato a parte)",
                      [n["archive"] for n in unmatched]))
    # classi del fornitore nei jar senza i sorgenti .java: non si possono verificare, correggere o ricompilare
    binary = {}
    for n in notes.get("binary_only") or []:
        jar, pkg, count = (n.split(";") + ["", "", "0"])[:3]
        binary.setdefault(jar, []).append((pkg, int(count) if count.isdigit() else 0))
    if binary:
        flags.append(("Alta", "Codice compilato senza sorgenti nel repository",
                      [f"{jar}: {', '.join(p for p, _ in pkgs[:3])} ({sum(n for _, n in pkgs)} classi)"
                       for jar, pkgs in sorted(binary.items())]))
    order = {"Alta": 0, "Media": 1}
    flags.sort(key=lambda f: order[f[0]])
    declared = any(c.source_kind for c in components)
    return {
        "nested": nested,
        "binary_only": sorted(binary),
        "applicable": bool(declared or flags or notes),
        "source_declared": declared,
        "flags": [{"severity": s, "title": t, "items": items} for s, t, items in flags],
        "non_official": len(non_official),
        "attested": sum(1 for c in evaluated if c.registry.get("attested")),
        "evaluated": len(evaluated),
        "unsupported": list(notes.get("unsupported") or []),
    }
