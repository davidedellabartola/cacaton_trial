"""Report in Markdown: gli stessi risultati della presentazione, in un testo da leggere o versionare.

Utile per allegare l'analisi a una issue, a un verbale o a una PEC, e per confrontare
piu' analisi (tabella di confronto quando si passano piu' input). Non richiede python-pptx.
"""

from ..model import SEVERITY_IT, SEVERITY_ORDER


def online_note(meta: dict) -> str:
    """Perche' non e' stato consultato nessun servizio online: per scelta o per mancanza di dati da verificare."""
    if meta.get("offline"):
        return "Nessun servizio online consultato (--offline)."
    return ("Nessun servizio online consultato, pur con la rete disponibile: non c'erano dipendenze da verificare "
            "sui registri e la sorgente non è un repository GitHub.")


def _pct(x):
    return f"{round(100 * x)}%"


def _cell(s, n=80):
    s = str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def _table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(_cell(c) for c in r) + " |" for r in rows]
    return out


def render(f: dict, meta: dict) -> str:
    sov = f["sovereignty"]
    git = meta.get("git") or {}
    out = [f"# {meta['target']}", ""]
    info = [f"Analisi del {meta['date']} con {meta['tool']}", f"Sorgente: {git.get('url') or meta['source']}"]
    if meta.get("version"):
        info.append(f"Versione dichiarata: {meta['version']}"
                    + (f" ({meta['version_from']})" if meta.get("version_from") else ""))
    if git.get("commit"):
        info.append(f"Commit: `{git['commit']}` ({git.get('ref', '')})")
    info.append(f"SBOM: {meta['sbom_format']} ({meta['engines']['sbom']}), {f['composition']['total']} {'componente' if f['composition']['total'] == 1 else 'componenti'}")
    out += [f"- {x}" for x in info] + [""]
    partial = f" — PARZIALE: {sov['measured']} {'dimensione' if sov['measured'] == 1 else 'dimensioni'} su {sov['possible']}" if sov.get("partial") else ""
    out += [f"**Indice di sovranità: {sov['index']}/100 ({sov['level']})**{partial}", ""]
    out += _table(["Dimensione", "Punteggio"],
                  [(k, f"{v}/100" if v >= 0 else "non misurabile") for k, v in sov["dimensions"].items()])

    v = f.get("vulns")
    if v is not None:
        out += ["", "## Vulnerabilità", "",
                f"{v['total']} vulnerabilità su {v['vulnerable_components']} "
                f"{'componente' if v['vulnerable_components'] == 1 else 'componenti'} "
                f"({_pct(v['component_ratio'])}); correggibili: {v['fixable']}; già sfruttate (KEV): {len(v['kev'])}; "
                f"EPSS ≥ 10%: {v['epss_high']}.", ""]
        out += _table([SEVERITY_IT[s] for s in SEVERITY_ORDER], [[v["by_severity"][s] for s in SEVERITY_ORDER]])
        if v.get("details_missing"):
            out += ["", f"_Attenzione: OSV.dev ha fornito i dettagli solo per una parte delle advisory; "
                        f"{v['details_missing']} restano senza gravità e correzione._"]
        if v["prioritized"]:
            out += ["", "Cosa correggere per primo:", ""]
            reach = any(x.reach for x in v["prioritized"])
            out += _table(["Vulnerabilità", "Componente", "Versione", "Gravità", "Corretta in", "KEV", "EPSS"]
                          + (["Uso nel progetto"] if reach else []),
                          [(x.id, x.component, x.version, SEVERITY_IT[x.severity],
                            ", ".join(x.fixed_in) if x.fix_state == "fixed" else "nessuna",
                            "Sì" if x.kev else "No", f"{round(100 * x.epss, 1)}%" if x.epss >= 0 else "n/d")
                           + ((x.reach or "probabile",) if reach else ())
                           for x in v["prioritized"][:10]])
            if reach:
                out.append("")
            for x in [x for x in v["prioritized"] if x.reach][:5]:
                out.append(f"- {x.id}: {x.reach_note}. Indizio, non prova: verificare.")

    lic = f["licenses"]
    out += ["", "## Licenze", ""]
    out += [f"- {k}: {n}" for k, n in lic["by_category"].items() if n]
    if lic.get("from_registry"):
        out.append(f"- licenze ricavate dal registro (deps.dev): {lic['from_registry']}")
    if lic.get("project_license"):
        out.append(f"- licenza del progetto: {lic['project_license']}")
    for x in lic.get("compatibility", []):
        more = f" (+{len(x['components']) - 6})" if len(x["components"]) > 6 else ""
        out.append(f"- **[{x['severity']}] {x['message']}**: {', '.join(x['components'][:6])}{more}")

    pv = f.get("provenance") or {}
    if pv.get("applicable"):
        out += ["", "## Provenienza dei componenti", ""]
        if not pv["flags"]:
            out.append("- Nessun segnale di provenienza opaca.")
        for x in pv["flags"]:
            more = f" (+{len(x['items']) - 6})" if len(x["items"]) > 6 else ""
            out.append(f"- **[{x['severity']}] {x['title']}**: {', '.join(x['items'][:6])}{more}")
        for n in [n for n in pv.get("nested", []) if n["status"] in ("identico", "illeggibile")]:
            out.append(f"- Pacchetto incluso {n['archive']}: {n['status']} {n['detail']}".rstrip())
        if pv.get("evaluated"):
            out.append(f"- Attestazioni di provenienza (SLSA): {pv['attested']} su {pv['evaluated']} "
                       f"{'dipendenza analizzata' if pv['evaluated'] == 1 else 'dipendenze analizzate'} "
                       "(solo informativo).")
        if pv.get("unsupported"):
            out.append("- File non letti dal motore integrato: " + "; ".join(pv["unsupported"]))

    cd = f.get("code") or {}
    if cd.get("applicable"):
        out += ["", "## Segnali nel codice del progetto", "",
                f"Controlli testuali su {cd['files']} file del progetto (escluso il codice di terzi copiato); "
                "non sostituiscono una revisione del codice.", ""]
        if not cd["findings"]:
            out.append("- Nessuna crittografia debole, credenziale nell'indirizzo o segreto in configurazione.")
        for x in cd["findings"]:
            more = f" (+{x['count'] - 4})" if x["count"] > 4 else ""
            out.append(f"- **[{x['severity']}] {x['title']}**: {', '.join(x['where'][:4])}{more}")
        if cd["endpoints"]:
            out.append("- Indirizzi esterni nel codice e nella configurazione: "
                       + ", ".join(f"{e['host']} ({e['where'][0]})" for e in cd["endpoints"][:8]))

    mt = f.get("maintenance") or {}
    out += ["", "## Manutenibilità delle dipendenze", ""]
    if mt.get("applicable"):
        out.append(f"Dipendenze valutate su deps.dev: {mt['evaluated']} — punteggio {mt['score']}/100.")
        for label, key in (("Senza release da oltre 18 mesi", "stale"), ("Deprecate", "deprecated"),
                           ("Indietro di 2 o più versioni maggiori", "behind")):
            if mt[key]:
                out.append(f"- {label} ({len(mt[key])}): " +
                           ", ".join(f"{x['name']} {x['version'] or ''} → {x['latest'] or '?'}".strip() for x in mt[key][:8]))
        if mt["vulnerable"]:
            out.append("- Con advisory note nella versione usata: " +
                       ", ".join(f"{x['name']} ({len(x['advisories'])})" for x in mt["vulnerable"][:8]))
    else:
        out.append("Non valutata: serve la rete (deps.dev) e dipendenze da registri pubblici.")

    gv = f.get("governance") or {}
    if gv.get("applicable"):
        out += ["", "## Governance", "", f"Segnali soddisfatti: {gv['score']}/100 tra quelli applicabili.", ""]
        sym = {True: "✓", False: "✗", None: "–"}
        out += _table(["", "Segnale", "Nota"], [(sym[s["ok"]], s["label"], s["note"]) for s in gv["signals"]])
        if gv.get("best_practices"):
            out += ["", f"Badge OpenSSF Best Practices: {gv['best_practices']}."]

    pl = f.get("pipeline") or {}
    if pl.get("applicable"):
        out += ["", "## Filiera di build", "",
                f"Punteggio {pl['score']}/100 — azioni bloccate per impronta {pl['actions_pinned']}/{pl['actions_total']}, "
                f"immagini con digest {pl['images_total'] - pl['images_unpinned']}/{pl['images_total']}, "
                f"firme nei rilasci: {'sì' if pl['has_signing'] else 'no'}; basi fuori supporto secondo "
                f"{pl.get('eol_source', 'tabella interna')}.", ""]
        if pl["findings"]:
            out += _table(["Gravità", "Problema", "Elemento", "Dove"],
                          [(x["severity"], x["kind"], x["text"], x["where"]) for x in pl["findings"][:20]])

    out += ["", "## Raccomandazioni", ""]
    labels = {1: "Subito", 2: "A breve", 3: "Da pianificare"}
    out += [f"{i}. **[{labels[p]}] {t}** — {b}" for i, (p, t, b) in enumerate(f["recommendations"], 1)]

    out += ["", "## Evidenze", "", f"- SHA-256 della SBOM: `{meta['sbom_sha256']}`",
            f"- Motore vulnerabilità: {meta['engines']['vulns']} (database: {meta['engines']['vulns_db']})"]
    if meta.get("online_sources"):
        out.append("- Servizi online consultati: " + ", ".join(meta["online_sources"]))
    else:
        out.append("- " + online_note(meta))
    out += [f"- Attenzione: {w}" for w in meta.get("warnings", [])]
    return "\n".join(out) + "\n"


def comparison(results: list) -> str:
    """Tabella di confronto tra piu' analisi (stesse dimensioni, una riga per input)."""
    dims = list(results[0]["findings"]["sovereignty"]["dimensions"])
    rows = []
    for r in results:
        s = r["findings"]["sovereignty"]
        rows.append([r["meta"]["target"], f"{s['index']}/100", s["level"] + (" (parziale)" if s.get("partial") else "")]
                    + [f"{s['dimensions'][d]}" if s["dimensions"][d] >= 0 else "n/d" for d in dims])
    return "\n".join(["## Confronto", ""] + _table(["Input", "Indice", "Livello"] + dims, rows)) + "\n"
