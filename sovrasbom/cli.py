"""Interfaccia a riga di comando: un argomento (o piu'), dall'analisi alla presentazione.

  python3 analizza.py <cosa-analizzare> [<altro> ...]

Esempi:
  python3 analizza.py https://github.com/maldua/zimbra-foss/tree/zimbra-foss-build-ubuntu-24.04/10.1.20.p1
  python3 analizza.py https://github.com/maldua/zimbra-foss/releases/tag/zimbra-foss-build-ubuntu-24.04%2F10.1.20.p1
  python3 analizza.py pagopa/io-app
  python3 analizza.py ./progetto.zip --last-commit 2025-09-30
  sudo python3 analizza.py /opt/zimbra --name "Zimbra 10.1.20 FOSS"
  python3 analizza.py sbom-fornitore.spdx.json
  python3 analizza.py docker:nginx:1.27
  python3 analizza.py progetto-a.zip progetto-b.zip --md confronto.md

Tutto il resto (nome, motori, cartella di output) viene scelto automaticamente;
le opzioni servono solo a cambiare le scelte predefinite. Con piu' input ogni analisi
ha la sua cartella di report e alla fine viene stampata una tabella di confronto.
"""

import argparse
import os
import shutil
import sys
from datetime import datetime

from . import __version__
from . import builtin_sbom, depsdev
from .analyzers import run_all
from .analyzers import vulns as vulns_mod
from .collect import (OSV_MAX_DETAILS, ToolMissing, generate_sbom, scan_vulnerabilities, sha256_file, tool_version,
                      vuln_db_info)
from .evidence import write_evidence, write_findings
from .report import markdown_report
from .sbom import load_sbom
from .target import resolve


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="analizza.py",
        description="Sicurezza e sovranità della supply chain software: dall'input alla presentazione .pptx.",
        epilog="Esempio: python3 analizza.py https://github.com/owner/repo/tree/v1.2.3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", metavar="target",
                   help="cartella, archivio .zip/.tar.gz, URL Git (anche /tree/<tag>), owner/repo, "
                        "SBOM (CycloneDX/SPDX) oppure docker:immagine:tag; anche più di uno")
    p.add_argument("--name", default="", help="nome nel titolo (default: ricavato dall'input; solo con un input)")
    p.add_argument("--org", default="", help="amministrazione o ente per cui si svolge l'analisi")
    p.add_argument("--ref", default="", help="tag, branch o commit da analizzare (per i repository Git)")
    p.add_argument("--asset", default="", help="file da analizzare in un rilascio GitHub (default: l'archivio più grande)")
    p.add_argument("--vendor-sbom", help="SBOM dichiarata dal fornitore da confrontare con quella rilevata")
    p.add_argument("--vulns-json", "--grype-json", dest="vulns_json",
                   help="risultati di Grype/Trivy già calcolati (salta la scansione)")
    p.add_argument("--engine", choices=["auto", "syft", "trivy", "integrato"], default="auto",
                   help="motore per la SBOM (default: il primo disponibile tra syft, trivy, integrato)")
    p.add_argument("--vuln-engine", choices=["auto", "grype", "trivy", "osv"], default="auto",
                   help="motore per le vulnerabilità (default: grype, poi trivy, poi OSV.dev)")
    p.add_argument("--no-vulns", action="store_true", help="non cercare vulnerabilità")
    p.add_argument("--offline", action="store_true",
                   help="nessun servizio online (niente KEV, EPSS, OSV.dev, deps.dev, Scorecard, endoflife.date)")
    p.add_argument("--max-deps", type=int, default=80,
                   help="dipendenze da interrogare su deps.dev, prima le dirette (default 80; 0 = tutte)")
    p.add_argument("--last-commit", metavar="AAAA-MM-GG", default="",
                   help="data dell'ultimo commit, per archivi senza storico git (segnale 'progetto attivo')")
    p.add_argument("--md", default="", metavar="FILE",
                   help="salva anche un report Markdown (con più input: tutti i report e la tabella di confronto)")
    p.add_argument("--out", default="", help="cartella di output (default: report-<nome>-<data>; "
                                             "con più input: una sottocartella per input)")
    p.add_argument("--sign", default="", metavar="KEYID", help="firma SHA256SUMS con questa chiave GPG")
    p.add_argument("--keep", action="store_true", help="non cancellare la copia temporanea scaricata")
    # compatibilita' con la versione 0.1
    p.add_argument("--source", help=argparse.SUPPRESS)
    p.add_argument("--sbom", help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version=f"sovrasbom {__version__}")
    args = p.parse_args(argv)
    args.targets = args.targets or [x for x in (args.source or args.sbom,) if x]
    if not args.targets:
        p.print_help()
        p.exit(2, "\nIndica che cosa analizzare, ad esempio: python3 analizza.py pagopa/io-app\n")
    if args.last_commit:
        try:
            datetime.strptime(args.last_commit, "%Y-%m-%d")
        except ValueError:
            p.error("--last-commit vuole una data nel formato AAAA-MM-GG")
    if len(args.targets) > 1 and args.name:
        p.error("--name vale per un solo input: con più input il nome viene ricavato da ciascuno")
    return args


def log(msg):
    print(f"[sovrasbom] {msg}", flush=True)


def _slug(text):
    s = "".join(ch if ch.isalnum() else "-" for ch in text.lower())
    return "-".join(part for part in s.split("-") if part)[:60] or "software"


def main(argv=None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    results, failures = [], 0
    for arg in args.targets:
        if len(args.targets) > 1:
            log(f"=== {arg} ===")
        try:
            target = resolve(arg, ref=args.ref, log=log, asset=args.asset)
        except (ValueError, RuntimeError) as exc:
            log(f"ERRORE: {exc}")
            failures += 1
            continue
        try:
            res = _run(args, target, arg, multi=len(args.targets) > 1)
        finally:
            if args.keep and target.temp_dirs:
                log(f"Copia scaricata conservata in: {target.temp_dirs[0]}")
            else:
                target.cleanup()
        if res is None:
            failures += 1
        else:
            results.append(res)
    if len(results) > 1:
        table = markdown_report.comparison(results)
        print("\n" + table)
    if args.md and results:
        text = "\n\n".join(r["markdown"] for r in results)
        if len(results) > 1:
            text += "\n" + markdown_report.comparison(results)
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text + "\n_Punteggi euristici automatici: da verificare con una revisione umana. "
                            "La compatibilità tra licenze non è consulenza legale._\n")
        log(f"Report Markdown: {args.md}")
    return 2 if failures and not results else (1 if failures else 0)


def _run(args, target, arg, multi=False):
    name = args.name or target.name
    log(f"Analizzo: {target.label}  ({target.kind})")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    auto_dir = f"report-{_slug(name)[:40].rstrip('-')}-{stamp}"
    out_dir = (os.path.join(args.out, auto_dir) if multi else args.out) if args.out else auto_dir
    os.makedirs(out_dir, exist_ok=True)
    commands, warnings, online_sources = [], [], []
    if args.last_commit and not (target.git or {}).get("commit_date"):
        # archivio senza storico git: la data dichiarata a mano vale per il segnale "progetto attivo"
        target.git = dict(target.git or {}, commit_date=args.last_commit, commit_date_source="--last-commit")
        warnings.append(f"Data dell'ultimo commit dichiarata a mano (--last-commit {args.last_commit}), non verificata")

    # ---------------------------------------------------------------- 1. SBOM
    if target.sbom_path:
        # copiamo la SBOM nella cartella del report: le evidenze devono essere autosufficienti
        sbom_path = os.path.join(out_dir, "sbom-input" + os.path.splitext(target.sbom_path)[1])
        shutil.copyfile(target.sbom_path, sbom_path)
        sbom_engine = "fornita"
    else:
        sbom_path = os.path.join(out_dir, "sbom.cdx.json")
        log("Genero la SBOM...")
        try:
            sbom_engine = generate_sbom(target, sbom_path, commands, args.engine)
        except ToolMissing as exc:
            log(f"ERRORE: {exc}")
            return None
        if sbom_engine == "integrato":
            warnings.append("SBOM generata dal motore integrato: riconosce file di dipendenze, pacchetti .deb "
                            "e librerie Java, ma non i binari compilati (es. OpenSSL): per quelli servono Syft o Trivy")
    sbom = load_sbom(sbom_path)
    dup_note = f" ({sbom.raw_count} voci prima di unire i duplicati)" if sbom.raw_count > len(sbom.components) else ""
    log(f"SBOM: {sbom.fmt}, {len(sbom.components)} componenti{dup_note} — motore: {sbom_engine}")
    if sbom.notes.get("unsupported"):
        warnings.append("File di dipendenze non letti: " + "; ".join(sbom.notes["unsupported"]))

    if not sbom.components and target.kind != "sbom":
        reasons = []
        if sbom_engine == "integrato":
            reasons.append("Syft e Trivy non trovati (cercati nel PATH, in ~/tools/<nome> e nelle cartelle di "
                           "SOVRASBOM_TOOLS) e il motore integrato non ha trovato componenti riconoscibili")
        pkg = target.extra.get("packages") or {}
        if any("zstd" in x for x in pkg.get("skipped", [])):
            reasons.append("pacchetti .deb non aperti: installa il modulo con 'python -m pip install zstandard' "
                           "nello stesso Python con cui lanci il tool")
        msg = "SBOM VUOTA: l'analisi del software è incompleta" + (" — " + "; ".join(reasons) if reasons else "")
        warnings.append(msg)
        log(f"ATTENZIONE: {msg}")

    vendor, vendor_copy = None, ""
    if args.vendor_sbom:
        vendor_copy = os.path.join(out_dir, "sbom-fornitore" + os.path.splitext(args.vendor_sbom)[1])
        shutil.copyfile(args.vendor_sbom, vendor_copy)
        vendor = load_sbom(vendor_copy)
        log(f"SBOM del fornitore: {vendor.fmt}, {len(vendor.components)} componenti")

    # ------------------------------------------------- 2. Registro (deps.dev)
    depsdev_info = None
    if sbom.components and not args.offline:
        log("Interrogo deps.dev (manutenzione, licenze, provenienza delle dipendenze)...")
        depsdev_info = depsdev.enrich(sbom.components, args.max_deps)
        if depsdev_info["queried"]:
            online_sources.append("deps.dev (registri dei pacchetti)")
            log(f"deps.dev: {depsdev_info['ok']} dipendenze valutate su {depsdev_info['queried']}"
                + (f", {depsdev_info['licenses_added']} licenze aggiunte" if depsdev_info["licenses_added"] else ""))
        if depsdev_info["licenses_added"]:
            if sbom_engine == "integrato":
                # la SBOM e' nostra: le licenze del registro vi vengono scritte, con la fonte dichiarata
                builtin_sbom.add_registry_data(sbom_path, sbom.components)
            else:
                warnings.append(f"{depsdev_info['licenses_added']} licenze ricavate da deps.dev non sono nella SBOM "
                                "allegata (che resta quella originale): sono elencate in risultati.json")
        if depsdev_info["errors"]:
            warnings.append(f"deps.dev: {depsdev_info['errors']} richieste non riuscite (rete o limiti del servizio): "
                            "manutenibilità e licenze parziali")
        if depsdev_info["skipped"]:
            warnings.append(f"deps.dev: interrogate le prime {args.max_deps} dipendenze, "
                            f"{depsdev_info['skipped']} escluse (--max-deps 0 per interrogarle tutte)")

    # --------------------------------------------------------- 3. Vulnerabilita'
    vulnerabilities, vulns_path, enrich_info = None, "", {}
    vuln_engine, vuln_db, details_missing = "non eseguita", "n/d", 0
    if args.no_vulns:
        vuln_engine = "non eseguita (--no-vulns)"
    elif not sbom.components:
        vuln_engine = "non necessaria (nessun componente)"
    else:
        vulns_path = os.path.join(out_dir, "vulnerabilita.json")
        if args.vulns_json:
            shutil.copyfile(args.vulns_json, vulns_path)
            vuln_engine = "risultati forniti"
        else:
            log("Cerco le vulnerabilità...")
            try:
                eng = scan_vulnerabilities(sbom_path, vulns_path, commands, args.vuln_engine, args.offline)
                vuln_engine = eng if eng == "osv" else f"{eng} {tool_version(eng)}"
                vuln_db = vuln_db_info(eng)
                if eng == "osv":
                    online_sources.append("OSV.dev (vulnerabilità)")
            except ToolMissing as exc:
                warnings.append(str(exc))
                log(f"ATTENZIONE: {exc}")
                vulns_path = ""
        if vulns_path:
            vulnerabilities, fmt = vulns_mod.load_results(vulns_path)
            log(f"Vulnerabilità trovate: {len(vulnerabilities)} (formato {fmt})")
            if fmt == "osv":
                details_missing, ids_total = vulns_mod.osv_missing_details(vulns_path)
                if details_missing:
                    msg = (f"OSV.dev: dettagli scaricati solo per {ids_total - details_missing} advisory su {ids_total} "
                           f"(limite {OSV_MAX_DETAILS}): {details_missing} restano senza gravità e correzione")
                    warnings.append(msg)
                    log(f"ATTENZIONE: {msg}")
            if args.offline:
                enrich_info = {"kev": "solo dati del motore", "epss": "solo dati del motore"}
            else:
                log("Arricchisco con CISA KEV ed EPSS...")
                enrich_info = vulns_mod.enrich(vulnerabilities, warnings)
                online_sources += ["CISA KEV", "FIRST EPSS"]

    # ------------------------------------------------------------ 4. Analisi
    if target.root:
        log("Analizzo governance e pipeline di build...")
    context = {"sbom_engine": sbom_engine, "offline": args.offline, "depsdev": depsdev_info}
    findings = run_all(sbom, vulnerabilities, vendor, target=target, online=not args.offline, context=context)
    if findings["vulns"] is not None:
        findings["vulns"]["details_missing"] = details_missing
    gv, pl = findings["governance"], findings["pipeline"]
    if gv.get("scorecard"):
        online_sources.append("OpenSSF Scorecard")
    if gv.get("github"):
        online_sources.append("API GitHub (proprietario, archiviazione)")
    if gv.get("best_practices") is not None:
        online_sources.append("OpenSSF Best Practices")
    if pl.get("eol_source") == "endoflife.date":
        online_sources.append("endoflife.date (immagini fuori supporto)")
    findings_path = write_findings(findings, os.path.join(out_dir, "risultati.json"))

    meta = {
        "tool": f"sovrasbom {__version__}",
        "target": name,
        "organization": args.org,
        "input": arg,
        "source": target.label,
        "kind": target.kind,
        "git": target.git,
        "archive_sha256": target.extra.get("archive_sha256", ""),
        "release": target.extra.get("release"),
        "packages": target.extra.get("packages"),
        "version": sbom.subject_version,
        "version_from": sbom.subject_version_from,
        "sbom_format": sbom.fmt,
        "sbom_generator": ", ".join(sbom.author_tools) or "non dichiarato",
        "sbom_sha256": sha256_file(sbom_path),
        "vulns_sha256": sha256_file(vulns_path) if vulns_path else "",
        "engines": {"sbom": sbom_engine, "vulns": vuln_engine, "vulns_db": vuln_db,
                    "syft": tool_version("syft"), "trivy": tool_version("trivy"), "grype": tool_version("grype")},
        "enrichment": enrich_info,
        "depsdev": depsdev_info,
        "online_sources": online_sources,
        "offline": args.offline,
        "commands": commands,
        "warnings": warnings,
        "date": datetime.now().strftime("%d/%m/%Y %H:%M"),
    }

    # -------------------------------------------- 5. Presentazione e Markdown
    pptx_path = os.path.join(out_dir, f"supply-chain-{_slug(name)[:40].rstrip('-')}.pptx")
    log("Genero la presentazione...")
    try:
        from .report.pptx_report import build_presentation
        build_presentation(findings, meta, pptx_path)
    except ImportError:
        warnings.append("python-pptx non installato: presentazione non generata (pip install -r requirements.txt)")
        log("ATTENZIONE: python-pptx non installato, genero solo il report Markdown")
        pptx_path = ""
    md_text = markdown_report.render(findings, meta)
    md_path = os.path.join(out_dir, "report.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(md_text)

    # ------------------------------------------------------------ 6. Evidenze
    files = [sbom_path, vendor_copy, vulns_path, findings_path, md_path, pptx_path]
    ev = write_evidence(meta, files, out_dir, args.sign)

    s = findings["sovereignty"]
    log("Fatto.")
    log(f"  Indice di sovranità: {s['index']}/100 ({s['level']})"
        + (f" — PARZIALE: {s['measured']} {'dimensione' if s['measured'] == 1 else 'dimensioni'} su {s['possible']}" if s.get("partial") else ""))
    for dim, val in s["dimensions"].items():
        if val >= 0:
            log(f"    {dim:<17} {val}/100")
    if pptx_path:
        log(f"  Presentazione: {pptx_path}")
    log(f"  Report:        {md_path}")
    log(f"  Evidenze:      {ev['evidence']}  +  {ev['sums']}")
    if ev["signature"]:
        log(f"  Firma:         {ev['signature']}")
    for w in ev["meta"].get("warnings", []):
        log(f"  Attenzione: {w}")
    return {"findings": findings, "meta": meta, "out_dir": out_dir, "markdown": md_text}

