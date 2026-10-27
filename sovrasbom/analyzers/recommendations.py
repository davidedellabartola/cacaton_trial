"""Raccomandazioni: trasforma i numeri in azioni per la PA.

Ogni regola ha una soglia esplicita: chi legge il codice vede esattamente
perche' una raccomandazione compare. Priorita': 1 = subito, 2 = a breve, 3 = da pianificare.
"""

import re


def _n(n, singular, plural):
    return f"{n} {singular if n == 1 else plural}"


def _cap(s):
    return s[:1].upper() + s[1:]


# librerie di crittografia per il browser: l'alternativa mantenuta e' la Web Crypto API del browser stesso
BROWSER_CRYPTO = {"crypto-js", "sjcl", "jsencrypt", "node-forge", "forge"}


def _components_to_replace(findings: dict) -> dict:
    """{nome: raccomandazione} per i componenti deprecati, o copiati nel repository e vulnerabili."""
    v = findings.get("vulns") or {}
    mt = findings.get("maintenance") or {}
    pv_copied = {x.split(" ")[0] for f in (findings.get("provenance") or {}).get("flags", [])
                 if f["title"].startswith("Codice di terzi") for x in f["items"]}
    deprecated = {x["name"]: x for x in mt.get("deprecated", [])}
    stale = {x["name"]: x for x in mt.get("stale", [])}
    by_comp = {}
    for x in v.get("prioritized", []):
        by_comp.setdefault(x.component, []).append(x)
    names = list(deprecated) + [n for n in by_comp if n in pv_copied and n not in deprecated]
    out = {}
    for name in names:
        vulns = by_comp.get(name, [])
        info = deprecated.get(name) or stale.get(name) or {}
        version = info.get("version") or (vulns[0].version if vulns else "")
        parts = []
        if name in deprecated:
            parts.append("è deprecata dall'autore")
        elif name in stale:
            parts.append(f"non ha release da {info['days']} giorni")
        if name in pv_copied:
            parts.append("è copiata nel repository, quindi non riceve correzioni")
        if vulns:
            unreached = [x for x in vulns if x.reach]
            parts.append(f"ha {_n(len(vulns), 'vulnerabilità nota', 'vulnerabilità note')} ("
                         + ", ".join(x.id for x in vulns[:3]) + ")"
                         + (f", di cui {len(unreached)} con la funzione vulnerabile non caricata o non chiamata dal "
                            "progetto" if unreached else ""))
        advice = ("Aggiornarla non basta: sostituirla con un'alternativa mantenuta"
                  + (" (nel browser: la Web Crypto API, con AES-GCM)" if name in BROWSER_CRYPTO else "")
                  + "." if name in deprecated else
                  f"Sostituire la copia con la versione {info.get('latest') or 'corretta'} installata dal registro, "
                  "con un lockfile, oppure documentare chi la aggiorna.")
        urgent = any(x.severity in ("Critical", "High") and not x.reach for x in vulns) or any(x.kev for x in vulns)
        out[name] = (1 if urgent else 2, f"Sostituire {name} {version}".strip(),
                     f"La libreria {name} {version} " + "; ".join(parts) + ". " + advice)
    return out


def build(findings: dict) -> list:
    recs = []
    v = findings.get("vulns")
    q = findings["quality"]
    lic = findings["licenses"]
    dup = findings["duplicates"]
    vd = findings.get("vendor_diff")
    pl = findings.get("pipeline") or {}
    gv = findings.get("governance") or {}

    if v and v["kev"]:
        recs.append((1, "Correggere le vulnerabilità già sfruttate",
                     f"{len(v['kev'])} vulnerabilità risultano nel catalogo CISA KEV, cioè usate in attacchi reali. "
                     "Richiedere al fornitore la patch o una mitigazione con scadenza contrattuale."))
    # una raccomandazione sola per componente da sostituire (deprecato, o copiato e vulnerabile):
    # aggiornarlo non basta, e tre voci separate sullo stesso componente confondono
    replace = _components_to_replace(findings)
    for name, r in replace.items():
        recs.append(r)
    fixable = [x for x in (v or {}).get("prioritized", []) if x.fix_state == "fixed" and not x.reach
               and x.severity in ("Critical", "High") and x.component not in replace]
    if fixable:
        recs.append((1, "Applicare gli aggiornamenti disponibili",
                     f"{_n(len(fixable), 'vulnerabilità critica o alta ha', 'vulnerabilità critiche o alte hanno')} "
                     "già una versione corretta. Il ritardo dipende solo dal ciclo di aggiornamento del fornitore."))
    if vd and (vd["undeclared"] or vd["mismatched"]):
        recs.append((1, "Contestare la SBOM del fornitore",
                     f"{len(vd['undeclared'])} componenti installati non sono dichiarati e "
                     f"{len(vd['mismatched'])} hanno versioni diverse da quelle dichiarate."))
    if pl.get("applicable"):
        if pl.get("injections"):
            recs.append((1, "Chiudere l'iniezione di comandi nei workflow",
                         _n(pl["injections"], "comando run: inserisce", "comandi run: inseriscono") +
                         " testo scritto da chiunque (titoli di issue, nomi di branch) tramite "
                         "${{ github.event... }}: passarlo in una variabile d'ambiente."))
        if pl.get("pr_target_high"):
            recs.append((1, "Rivedere i workflow pull_request_target",
                         "Un workflow esegue con i segreti del progetto il codice proposto da contributori esterni: "
                         "usare pull_request oppure non scaricare il codice della PR."))
        if pl["pipe_to_shell"]:
            recs.append((1, "Eliminare i 'curl | bash' dalla build",
                         f"{pl['pipe_to_shell']} punti della build eseguono codice scaricato senza verificarlo: "
                         "sostituirli con pacchetti firmati o file con impronta verificata."))
        if pl["actions_third_party_unpinned"] or pl["images_unpinned"]:
            recs.append((2, "Bloccare la pipeline per impronta, non per etichetta",
                         f"{pl['actions_total'] - pl['actions_pinned']} azioni e {pl['images_unpinned']} immagini sono "
                         "indicate per tag, che il proprietario può spostare. Usare l'hash del commit e il digest sha256."))
        if pl.get("images_eol"):
            recs.append((2, "Abbandonare le basi fuori supporto",
                         f"{pl['images_eol']} immagini di base non ricevono più aggiornamenti di sicurezza."))
        if not pl["has_signing"]:
            recs.append((2, "Chiedere rilasci firmati e attestati",
                         "La build non firma i rilasci: richiedere firma (es. Sigstore/cosign), attestazione "
                         "di provenienza SLSA e SBOM pubblicata insieme a ogni versione."))
    rel = findings.get("release") or {}
    if rel:
        if rel.get("checksum_match") is False or rel.get("github_digest_match") is False:
            recs.append((1, "Non installare: impronta diversa",
                         "Il file scaricato non corrisponde all'impronta pubblicata: può essere corrotto o "
                         "manomesso. Scaricarlo di nuovo e segnalarlo al fornitore."))
        elif not rel.get("signatures"):
            recs.append((2, "Verificare l'integrità da un canale indipendente",
                         "Il rilascio non è firmato: l'impronta pubblicata accanto al file protegge dalla "
                         "corruzione, non da chi controlla l'account che pubblica."))
    if gv.get("applicable"):
        hist = gv.get("history")
        if hist and hist["top_author_share"] > 0.6:
            recs.append((2, "Ridurre la dipendenza da una sola persona",
                         f"Il {round(100 * hist['top_author_share'])}% dei commit recenti è di un solo autore: "
                         "valutare un accordo di manutenzione o un piano di subentro."))
        missing = [s["label"] for s in gv["signals"] if s["ok"] is False and
                   s["label"].startswith(("Canale", "publiccode"))]
        if missing:
            recs.append((3, "Completare i documenti di riuso",
                         "Mancano: " + "; ".join(missing) + ". Sono richiesti per il catalogo Developers Italia "
                         "e per sapere a chi segnalare una vulnerabilità."))
    if dup["count"]:
        recs.append((2, "Gestire le librerie incorporate",
                     (f"{dup['count']} componenti esistono" if dup["count"] > 1 else "1 componente esiste") +
                     " in più versioni. Le copie incorporate dal fornitore "
                     "non vengono aggiornate dal sistema operativo: chiedere chi le mantiene e con quali tempi."))
    if not findings["composition"]["total"]:
        recs.append((1, "Generare l'inventario dei componenti",
                     "La SBOM è vuota: senza inventario non si possono valutare vulnerabilità, licenze e origine. "
                     "Ripetere l'analisi con Syft o Trivy installati, che riconoscono anche i binari; se il software "
                     "include librerie copiate a mano, chiedere al fornitore l'elenco con nome e versione."))
    elif q["score"] < 80:
        recs.append((2, "Pretendere una SBOM completa nel contratto",
                     f"La SBOM raggiunge {q['score']}/100 sugli elementi minimi. Inserire nei capitolati "
                     "l'obbligo di SBOM CycloneDX/SPDX completa e aggiornata a ogni rilascio (CRA, dic. 2027)."))
    # Licenza "assente" perche' nessuno l'ha cercata (motore integrato offline) e' un limite dell'analisi,
    # non del software: va detto in modo diverso, senza attribuirlo al fornitore.
    if lic.get("not_searched"):
        recs.append((3, "Completare il dato sulle licenze",
                     f"Per il {round(100 * lic['missing_ratio'])}% dei componenti i file di dipendenze non riportano "
                     "la licenza e il registro non è stato consultato (analisi offline). Ripetere l'analisi in rete "
                     "(deps.dev) o con Syft/Trivy prima di trarre conclusioni."))
    elif lic["unknown_ratio"] > 0.2:
        recs.append((2, "Chiarire le licenze mancanti",
                     f"Il {round(100 * lic['unknown_ratio'])}% dei componenti non ha una licenza riconosciuta. "
                     "Senza licenza chiara la PA non sa se può modificare, riusare o far mantenere il software ad altri."))
    # le licenze non open source hanno gia' la loro raccomandazione ("componenti non liberi")
    high_compat = [x for x in lic.get("compatibility", [])
                   if x["severity"] == "Alta" and not x["message"].startswith("licenza non open source")]
    if high_compat:
        n = sum(len(x["components"]) for x in high_compat)
        recs.append((1, "Risolvere le incompatibilità di licenza",
                     f"{_n(n, 'componente ha una licenza incompatibile', 'componenti hanno licenze incompatibili')} "
                     f"con quella del progetto ({lic.get('project_license')}): "
                     + "; ".join(x["message"] for x in high_compat[:2]) + ". Far verificare all'ufficio legale."))
    elif any(x["severity"] == "Media" for x in lic.get("compatibility", [])):
        recs.append((2, "Verificare gli obblighi delle licenze copyleft",
                     "; ".join(x["message"] for x in lic["compatibility"] if x["severity"] == "Media")[:180] + "."))
    pv = findings.get("provenance") or {}
    copyleft = re.match(r"(A|L)?GPL|EUPL|MPL", gv.get("license") or "")
    advice = {
        "Codice di terzi": "Una copia non riceve le correzioni: installarla dal registro con un lockfile, oppure "
                           "documentare chi la aggiorna e con quali tempi.",
        "Codice compilato": "Senza sorgenti la PA non può verificarlo, correggerlo o farlo mantenere ad altri: "
                            "chiedere al fornitore i sorgenti e le istruzioni per ricompilarlo"
                            + (f" (la licenza {gv.get('license')} lo richiede)." if copyleft else "."),
        "Pacchetto da installare": "Chiedere al fornitore da quali sorgenti è stato costruito il pacchetto e "
                                   "installare solo un pacchetto ricostruito dai sorgenti pubblicati.",
    }
    titles = {"Codice compilato": "Chiedere i sorgenti del codice compilato",
              "Pacchetto da installare diverso": "Verificare il pacchetto da installare: è diverso dai sorgenti"}
    for flag in pv.get("flags", [])[:3]:
        if flag["title"].startswith("Codice di terzi"):
            # i componenti da sostituire hanno gia' la loro raccomandazione
            flag = dict(flag, items=[x for x in flag["items"] if x.split(" ")[0] not in replace])
            if not flag["items"]:
                continue
        title = next((t for k, t in titles.items() if flag["title"].startswith(k)),
                     "Provenienza da verificare: " + flag["title"].split(" (")[0].lower())
        recs.append((1 if flag["severity"] == "Alta" else 2, title,
                     _n(len(flag["items"]), "caso", "casi") + ": " + ", ".join(flag["items"][:3]) + ". " +
                     next((a for k, a in advice.items() if flag["title"].startswith(k)),
                          "Usare solo registri ufficiali con hash di integrità, oppure documentare chi mantiene "
                          "la copia.")))
    if pv.get("unsupported"):
        recs.append((3, "Completare l'inventario: file non letti",
                     "Il motore integrato non ha potuto leggere: " + "; ".join(pv["unsupported"][:3]) +
                     ". Le dipendenze dichiarate lì non sono nella SBOM: usare Syft/Trivy o aggiungere un lockfile."))
    mt = findings.get("maintenance") or {}
    stale_left = [x for x in mt.get("stale", []) if x["name"] not in replace]
    dep_left = [x for x in mt.get("deprecated", []) if x["name"] not in replace]
    if mt.get("applicable") and (stale_left or dep_left):
        mt = dict(mt, stale=stale_left, deprecated=dep_left)
        names = list(dict.fromkeys(x["name"] for x in (mt["deprecated"] + mt["stale"])))[:4]
        recs.append((2, "Sostituire le dipendenze non più mantenute",
                     " e ".join(x for x in (
                         f"{_n(len(mt['stale']), 'dipendenza', 'dipendenze')} senza release da oltre 18 mesi"
                         if mt["stale"] else "",
                         _n(len(mt["deprecated"]), "deprecata", "deprecate") if mt["deprecated"] else "") if x)
                     + f" (es. {', '.join(names)}): una futura vulnerabilità potrebbe restare senza correzione."))
    if gv.get("applicable"):
        if (gv.get("github") or {}).get("archived"):
            recs.append((1, "Il repository è archiviato",
                         "Il progetto è in sola lettura: non riceverà più correzioni. Pianificare la migrazione o "
                         "un fork mantenuto con un fornitore."))
        if (gv.get("exit") or {}).get("from_vendor"):
            recs.append((2, "Ottenere ciò che oggi va chiesto al fornitore",
                         "La documentazione dice: «" + gv["exit"]["from_vendor"][0] + "». Senza questo elemento il "
                         "software non funziona: chiedere che sia consegnato alla PA o generabile da essa, con la "
                         "procedura documentata, altrimenti non si può cambiare fornitore."))
        elif not (gv.get("exit") or {}).get("ok"):
            recs.append((3, "Chiedere una strategia di uscita",
                         "La documentazione non spiega come esportare i dati o migrare verso un altro sistema. "
                         "Chiedere formati aperti, procedure di export e backup documentati (non-lock-in, CAD art. 68)."))
    if lic["proprietary"]:
        recs.append((2, "Valutare la dipendenza da componenti non liberi",
                     f"{_n(len(lic['proprietary']), 'componente ha una licenza proprietaria o con restrizioni d’uso', 'componenti hanno licenze proprietarie o con restrizioni d’uso')}"
                     f" ({', '.join(x[0] for x in lic['proprietary'][:3])}): "
                     "verificare clausole di uscita e alternative (CAD artt. 68-69)."))
    cd = findings.get("code") or {}
    for x in [x for x in cd.get("findings", []) if x["severity"] == "Alta"][:4]:
        title = x["title"].split(" (")[0]
        fix = {"Crittografia debole": "Sostituirla con AES-GCM e chiavi diverse per utente, gestite lato server.",
               "Credenziali inserite nell'indirizzo": "Passarle in una richiesta POST o con un token monouso "
                                                      "a scadenza breve.",
               "Segreto della configurazione letto dal codice nel browser":
                   "Un segreto inviato al browser non è più segreto: spostare cifratura e firma sul server.",
               "Indirizzo costruito con un parametro della richiesta":
                   "Il server può essere usato per raggiungere sistemi interni: ammettere solo indirizzi da un "
                   "elenco configurato sul server, mai dalla richiesta.",
               "Percorso di file costruito con un parametro della richiesta":
                   "Con '../' si leggono o scrivono file fuori dalla cartella prevista: usare nomi generati dal "
                   "server o verificare che il percorso finale resti nella cartella.",
               "Proxy o CORS aperto": "Indicare solo i domini necessari al funzionamento, non '*'.",
               "Credenziali inviate in HTTP non cifrato": "Usare solo HTTPS con verifica del certificato."}
        advice = next((v for k, v in fix.items() if title.startswith(k)), "Correggere prima della messa in esercizio.")
        where = (", ".join(x["where"][:2]) + "." if title.startswith("Segreto") else
                 f"{'Un punto' if x['count'] == 1 else str(x['count']) + ' punti'} nel codice o nella configurazione del progetto (es. {', '.join(x['where'][:2])}).")
        # niente maiuscola automatica: storpierebbe i nomi di file e chiavi (it_seacom_... -> It_seacom_...)
        recs.append((1, title, f"{where} {advice}"))
    if gv.get("applicable") and (gv.get("license_extra_terms") or gv.get("license_conflicts")):
        parts = []
        if gv.get("license_extra_terms"):
            parts.append(f"la licenza {gv['license']} ha termini aggiuntivi ({gv['license_extra_terms']})")
        for l, fs in list((gv.get("license_conflicts") or {}).items())[:2]:
            parts.append(f"{_n(len(fs), 'file dichiara', 'file dichiarano')} {l} nell'intestazione")
        recs.append((2, "Chiarire la licenza del progetto",
                     _cap("; ".join(parts)) + ". Chiedere al fornitore quale licenza vale e se i termini "
                     "aggiuntivi limitano modifica, riuso o cambio di manutentore. Far verificare all'ufficio legale."))
    hosts = [e["host"] for e in cd.get("endpoints", [])]
    if hosts:
        recs.append((2, "Verificare i servizi esterni da cui dipende il software",
                     f"Il codice e la configurazione puntano a {_n(len(hosts), 'indirizzo esterno', 'indirizzi esterni')}: "
                     + ", ".join(hosts[:5]) + ". Per ognuno verificare chi lo gestisce, dove sono i dati, il contratto "
                     "e cosa succede se il servizio cambia o chiude; completare con l'analisi del traffico in uscita."))
    else:
        recs.append((3, "Verificare giurisdizione e dipendenze a runtime",
                     "La SBOM non dice dove hanno sede i fornitori né quali servizi esterni il software contatta. "
                     "Completare con analisi del traffico in uscita e due diligence sui fornitori principali."))
    recs.append((3, "Ripetere l'analisi a ogni rilascio",
                 "Il tool è ripetibile e produce evidenze con hash: confrontare i risultati nel tempo "
                 "per misurare se il fornitore migliora."))
    recs.sort(key=lambda r: r[0])
    return recs
