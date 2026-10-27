# SovraSBOM

**Sicurezza e sovranità della supply chain del software nella PA.**
Un solo comando, un solo argomento: il tool capisce da solo che cosa gli passi, genera o legge la SBOM, analizza componenti, vulnerabilità, provenienza, manutenzione delle dipendenze, governance e pipeline di build, e produce una **presentazione PowerPoint** e un **report Markdown** con le **evidenze verificabili** (impronte SHA-256, commit esatto, comandi, versioni degli strumenti).

```bash
python3 analizza.py https://github.com/maldua/zimbra-foss/tree/zimbra-foss-build-ubuntu-24.04/10.1.20.p1
```

| Pilastro della sfida | Cosa misura il tool |
|---|---|
| **Provenienza** | origine di ogni componente (registro ufficiale, git, URL, percorso locale), indici pip alternativi e `replace` di Go, lockfile senza hash, codice copiato nel repository (`vendor/`, `third_party/`, `lib/<nome versione>`, librerie JavaScript note riconosciute dall'intestazione, `.min.js`/`-min.js`), pacchetti assenti dal registro pubblico (dependency confusion), commit esatto, come nasce il binario (pipeline: azioni e immagini bloccate per impronta, `curl \| bash`, iniezione di comandi, `pull_request_target`, permessi, basi fuori supporto, firme) |
| **Composizione** | inventario per ecosistema, vulnerabilità (Grype / Trivy / OSV.dev + CISA KEV + EPSS), dipendenze non mantenute, deprecate o molto indietro (deps.dev), librerie incorporate in più versioni |
| **Governance** | licenze e loro compatibilità con quella del progetto, qualità della SBOM (elementi minimi NTIA), SBOM pubblicate nel repository (validate), chi mantiene il progetto, organizzazione o singolo utente, repository archiviato, SECURITY.md, CODEOWNERS, CODE_OF_CONDUCT, `publiccode.yml`, OpenSSF Scorecard e Best Practices, strategia di uscita (esportazione e migrazione dei dati), confronto con la SBOM del fornitore |
| **Codice del progetto** | crittografia debole (DES/3DES, RC4, ECB, MD5), segreti nei file di configurazione e segreti letti dal JavaScript (quindi visibili nel browser), credenziali nell'indirizzo, indirizzi dei servizi esterni da cui il software dipende (i link mostrati all'utente sono esclusi); per le librerie copiate, quali file il progetto carica davvero e se la funzione citata da un advisory è caricata e chiamata; pacchetti `.zip` inclusi nei sorgenti, confrontati file per file con la cartella corrispondente |
| **Verificabilità** | `evidenze.json`, `SHA256SUMS`, firma GPG opzionale, formule dell'indice pubbliche |

---

## 1. Installazione

Serve Python 3.10+ e la libreria `python-pptx` (consigliato Python 3.11+: su 3.10 manca `tomllib` e i file `pyproject.toml` non vengono letti; il report lo dichiara tra i "file non letti"). Conviene un ambiente virtuale (su Arch/CachyOS è obbligatorio):

```bash
cd sovrasbom
python3 -m venv .venv
source .venv/bin/activate            # fish: source .venv/bin/activate.fish
pip install -r requirements.txt
```

`requirements.txt` installa anche `cvss`, che calcola il punteggio CVSS v4 delle advisory OSV.dev (senza, la gravità viene presa dall'etichetta dell'advisory). Se `python-pptx` manca, il tool produce comunque il report Markdown.

**Strumenti esterni (facoltativi ma consigliati).** Il tool usa il primo disponibile:

| Compito | 1ª scelta | 2ª scelta | Ultima risorsa (nessuna installazione) |
|---|---|---|---|
| Generare la SBOM | Syft | Trivy | motore integrato: file di dipendenze, pacchetti `.deb`, librerie Java (non i binari compilati) |
| Trovare vulnerabilità | Grype | Trivy | OSV.dev (servizio online) |

Gli strumenti vengono cercati nel PATH e, se lì non ci sono, in `~/tools/<nome>/`, `~/tools/`, `~/bin/` e nelle cartelle elencate nella variabile `SOVRASBOM_TOOLS`. Per un'analisi completa di un sistema installato servono comunque Syft o Trivy, che riconoscono anche i binari compilati. Installa gli strumenti **verificando il checksum** (vedi le istruzioni dei rilasci su GitHub), poi `grype db update` per scaricare il database.

**Il motore integrato** legge: npm (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), Python (`requirements*.txt` e `requirements/*.txt` con `-e` e indici alternativi, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pyproject.toml` con `optional-dependencies` e gruppi Poetry), Go (`go.mod` con `replace`), Cargo, Composer, Maven (`pom.xml` con `dependencyManagement`), Gradle (`gradle.lockfile`), Ruby, NuGet (`packages.lock.json`, `packages.config`, `*.csproj`), C/C++ (`vcpkg.json`, `conanfile.txt`, submodule git e cartelle vendored), pacchetti `.deb` e librerie Java. Ciò che non sa leggere (es. `build.gradle` senza lockfile, `conanfile.py`, `setup.py`) compare nel report come **file non letti**.

## 2. Uso

```bash
python3 analizza.py <cosa-analizzare> [<altro> ...]
```

Il tool riconosce automaticamente:

| Input | Esempio |
|---|---|
| **Rilascio GitHub** (il binario pubblicato) | `https://github.com/owner/repo/releases/tag/v1.2.3` |
| Repository Git, anche su un tag preciso | `https://github.com/owner/repo/tree/v1.2.3` · `https://gitlab.com/gruppo/repo/-/tree/main` |
| Scorciatoia GitHub | `pagopa/io-app` |
| Cartella (sorgenti o software installato) | `./progetto` · `/opt/zimbra` (con `sudo`) |
| Archivio o pacchetto | `progetto.zip` · `zcs-10.1.20_GA_....tgz` · `pacchetto.deb` |
| SBOM già pronta | CycloneDX (JSON o XML), SPDX (JSON o tag-value): `sbom-fornitore.spdx.json`, `bom.xml`, `sbom.spdx` |
| Immagine container | `docker:nginx:1.27` |

Con **più input** ogni analisi ha la sua cartella di report e alla fine viene stampata una **tabella di confronto** (indice e dimensioni affiancate):

```bash
python3 analizza.py fornitore-a.zip fornitore-b.zip --md confronto.md
```

Opzioni (tutte facoltative):

| Opzione | A cosa serve |
|---|---|
| `--name "..."` | titolo della presentazione (default: ricavato dall'input; solo con un input) |
| `--org "..."` | ente per cui si svolge l'analisi |
| `--ref TAG` | tag, branch o commit del repository |
| `--asset NOME` | file da analizzare in un rilascio GitHub (default: l'archivio più grande) |
| `--vendor-sbom file` | confronta la SBOM dichiarata dal fornitore con quella reale |
| `--md FILE` | salva anche un report Markdown unico (con più input: tutti i report e il confronto) |
| `--last-commit AAAA-MM-GG` | data dell'ultimo commit per gli archivi senza storico git (segnale "progetto attivo"; resta segnata come dichiarata a mano) |
| `--max-deps N` | dipendenze da interrogare su deps.dev, prima le dirette (default 80; 0 = tutte) |
| `--offline` | nessun servizio online (niente deps.dev, KEV, EPSS, OSV.dev, Scorecard, API GitHub, endoflife.date) |
| `--engine` / `--vuln-engine` | forza un motore (`syft`, `trivy`, `integrato` / `grype`, `trivy`, `osv`) |
| `--vulns-json file` | riusa risultati di Grype o Trivy già calcolati |
| `--no-vulns` | salta la ricerca delle vulnerabilità |
| `--sign KEYID` | firma `SHA256SUMS` con GPG |
| `--keep` | conserva la copia scaricata del repository |
| `--out DIR` | cartella di output (con più input: una sottocartella per input) |

**Servizi online** (tutti gratuiti e senza chiave; `GITHUB_TOKEN` alza i limiti dell'API GitHub da 60 richieste/ora):

| Servizio | A cosa serve |
|---|---|
| deps.dev | ultima release, deprecazione, advisory, licenze dal registro, repository sorgente, attestazioni SLSA; pacchetti assenti dal registro pubblico. Risposte in cache in `~/.cache/sovrasbom/depsdev.json` per 7 giorni |
| OSV.dev, CISA KEV, FIRST EPSS | vulnerabilità (se mancano Grype e Trivy), sfruttamento reale, probabilità di attacco |
| API GitHub, OpenSSF Scorecard, OpenSSF Best Practices | proprietario (organizzazione o utente), repository archiviato, pratiche di sicurezza |
| endoflife.date | quali immagini di base sono fuori supporto (offline: tabella interna aggiornata a ottobre 2026) |

**Rilasci GitHub.** È l'analisi più vicina a ciò che una PA installa davvero. Il tool:
1. chiede a GitHub l'elenco dei file del rilascio (API pubblica: 60 richieste/ora, di più impostando `GITHUB_TOKEN`);
2. scarica l'archivio e ne calcola l'impronta SHA-256, confrontandola con **due fonti distinte**: il file `.sha256` pubblicato dall'autore e il *digest* che GitHub calcola da solo al caricamento;
3. registra se il rilascio contiene firme o attestazioni (`.asc`, `.sig`, `.sigstore`, `.intoto.jsonl`...);
4. estrae l'archivio e **apre i pacchetti `.deb`**: senza aprirli si vedono solo nomi e versioni dei pacchetti, aprendoli si vedono le librerie Java, i binari, OpenSSL incorporato;
5. clona il repository allo stesso tag: SBOM e vulnerabilità vengono dal binario, governance e pipeline dal codice che lo produce.

Lo stesso trattamento (estrazione e apertura dei `.deb`) vale se passi direttamente il file `zcs-...tgz` già scaricato.

**Note sui repository.** Il clone è "parziale": scarica tutta la storia dei commit (serve a misurare chi mantiene il progetto) ma solo i file della versione richiesta. Nei tag possono comparire delle `/` (come in quelli di Maldua): il tool chiede al server l'elenco reale dei riferimenti e sceglie quello giusto. Il codice scaricato viene solo **letto**, mai eseguito, e la copia temporanea viene cancellata alla fine.

## 3. Cosa produce

```
report-<nome>-<data>/
├── supply-chain-<nome>.pptx   ← la presentazione (grafici nativi, note per il relatore)
├── report.md                  ← gli stessi risultati in Markdown
├── sbom.cdx.json              ← SBOM analizzata (o sbom-input.* se fornita)
├── sbom-fornitore.*           ← SBOM dichiarata (se fornita)
├── vulnerabilita.json         ← risposte grezze del motore di vulnerabilità
├── risultati.json             ← tutti i numeri della presentazione, leggibili da macchina
├── evidenze.json              ← input, commit, comandi, versioni degli strumenti, servizi online usati
└── SHA256SUMS (+ .asc)        ← verifica:  sha256sum -c SHA256SUMS
```

Slide: titolo con indice, sintesi, indice di sovranità, **il pacchetto che si installa** (solo per i rilasci), composizione, qualità della SBOM, vulnerabilità, priorità di intervento, componenti più esposti, licenze (con compatibilità), **provenienza opaca**, **manutenibilità delle dipendenze**, librerie in più versioni, confronto con il fornitore, **governance**, **come nasce il binario**, raccomandazioni, metodologia. Le slide senza dati vengono saltate o mostrano un esito esplicito.

## 4. Indice di sovranità (formule)

Fino a sette dimensioni da 0 a 100; l'indice è la media di quelle **misurabili** per quell'input (una dimensione senza dati viene esclusa, non contata come zero). Soglie: ≥75 buono, 50–74 da migliorare, <50 critico. Con meno di tre dimensioni misurate il numero si calcola ma il livello è **Non classificabile**: una media su una o due dimensioni non è un giudizio sul software.

- **Trasparenza** = 80% × copertura media di fornitore, nome, versione, identificativo univoco + 20% × presenza di autore, data e dipendenze nel documento
- **Apertura** = % componenti con licenza open source riconosciuta (non misurabile se oltre l'80% dei componenti non dichiara la licenza, o se le licenze non sono state cercate: motore integrato senza deps.dev)
- **Tracciabilità** = % componenti con identificativo univoco **e** origine nota (namespace, fornitore o registro ufficiale implicito nel purl) **e** provenienza non opaca (non da git, URL, percorsi locali o registri alternativi)
- **Sicurezza** = 100 − 30 (se c'è almeno una vulnerabilità KEV) − min(40, 4×critiche + 1×alte) − 30 × quota di componenti vulnerabili − min(30, 10 × segnali gravi nel codice del progetto). Una critica o alta in una libreria copiata la cui funzione vulnerabile non è caricata o non è chiamata dal progetto pesa un quarto
- **Manutenibilità** = 100 − 200 × quota di dipendenze senza release da 18 mesi o deprecate − 50 × quota indietro di 2+ versioni maggiori (solo online, dati deps.dev)
- **Governance** = % dei segnali applicabili soddisfatti: licenza, licenza OSI, stessa licenza nelle intestazioni dei sorgenti, README, docs/, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY.md, CODEOWNERS, CI (anche CircleCI), test, lockfile, `publiccode.yml`, SBOM pubblicata valida e completa (≥80%), **strategia di uscita** (licenza OSI e almeno due riferimenti a esportazione, migrazione, backup o standard aperti in README e docs/), nessuna chiave, passphrase o attivazione da chiedere al fornitore (frasi del README e di docs/), attività recente, repository non archiviato, proprietà di un'organizzazione, almeno 5 autori, nessun autore oltre il 60% dei commit, OpenSSF Scorecard ≥ 5. I segnali non verificabili (es. senza rete o senza storico git) non entrano nel punteggio
- **Filiera di build** = 100 − penalità con tetto per categoria: `curl | bash` 25, azioni di autori esterni non bloccate 25, iniezione di comandi `${{ github.event... }}` 20, azioni ufficiali non bloccate 10, immagini senza digest 10, `pull_request_target` 10 (5 se non scarica il codice della PR), workflow senza `permissions:` 10, basi fuori supporto 15, nessuna firma dei rilasci 15

La compatibilità tra licenze usa una tabella **semplificata** (GPL-2.0-only con Apache-2.0 e GPL-3.0, AGPL nei servizi di rete, copyleft forte in un progetto permissivo, progetti EUPL): non è consulenza legale. La licenza del progetto è letta dal file LICENSE oppure da `package.json`, `Cargo.toml`, `pyproject.toml`. Il report segnala anche i **termini aggiuntivi** scritti prima del testo standard (es. AGPL "supplemented" secondo la sezione 7, Commons Clause) e le intestazioni dei sorgenti che dichiarano un'altra licenza.

Le formule sono nel codice (`sovrasbom/analyzers/`): un indice che non si può ricalcolare non è verificabile.

Rispetto alla griglia 0–2 di `sovereignty_check.py` (totale su 10): "Provenienza" corrisponde a Tracciabilità + slide Provenienza opaca, "SBOM" a Trasparenza + segnale "SBOM pubblicata", "Governance" e "Strategia di uscita" alla dimensione Governance, "Manutenibilità" alla dimensione omonima.

## 5. Struttura del codice

```
analizza.py             lanciatore: python3 analizza.py <input> [<input> ...]
sovrasbom/
├── cli.py              opzioni e sequenza: input → SBOM → deps.dev → vulnerabilità → analisi → slide/Markdown → evidenze
├── target.py           riconoscimento dell'input, clone Git, estrazione sicura degli archivi
├── release.py          rilasci GitHub: elenco file, download, verifica impronte, firme
├── debpkg.py           apertura dei pacchetti .deb (gz, xz, bz2, zstd)
├── collect.py          motori: Syft/Trivy/integrato per la SBOM, Grype/Trivy/OSV per le vulnerabilità
├── builtin_sbom.py     motore integrato (parser adattati da sovereignty_check.py) + note sui file non letti
├── depsdev.py          arricchimento online con deps.dev, con cache su disco
├── sbom.py             lettura CycloneDX (JSON/XML) e SPDX (JSON/tag-value), validazione delle SBOM pubblicate
├── model.py            Component, Sbom, Vulnerability
├── analyzers/          un file per punto di vista: composition, quality, licenses, duplicates, vulns,
│                       vendor_diff, provenance, maintenance, governance, pipeline, code, sovereignty, recommendations
├── report/             style.py (colori e font) + pptx_report.py (le slide) + markdown_report.py
└── evidence.py         evidenze.json, SHA256SUMS, firma GPG
tests/                  test automatici (pytest) su piccoli repository di esempio, senza rete
```

Per aggiungere un controllo: nuovo file in `analyzers/`, chiamalo in `analyzers/__init__.py`, aggiungi la sua slide in `report/pptx_report.py` e la sezione in `report/markdown_report.py`, poi un test in `tests/`.

**Test.** `pip install -r requirements-dev.txt` e poi `python -m pytest` dalla cartella `sovrasbom/`. I test costruiscono al volo piccoli repository (npm con fonti non ufficiali, pip con indici alternativi, vcpkg/Conan, Maven, workflow con iniezione di comandi...) e non usano la rete. Girano anche nella CI del repository (`.github/workflows/sovrasbom-tests.yml`).

## 6. Prova senza rete (dati sintetici)

```bash
python3 demo/genera_dati_demo.py
python3 analizza.py demo-sbom.cdx.json --vulns-json demo-grype.json \
        --vendor-sbom demo-vendor.spdx.json --name "Zimbra (DEMO)" --offline
```

⚠️ I dati demo sono **inventati** (vulnerabilità `CVE-DEMO-xxxx`): servono a provare il tool, non vanno presentati come risultati reali.

## 7. Limiti dichiarati

- La SBOM descrive i componenti, non il comportamento: dipendenze di rete a runtime e giurisdizione dei fornitori richiedono analisi aggiuntive. Gli indirizzi esterni trovati nel codice sono un punto di partenza, non l'elenco completo.
- I segnali nel codice sono controlli testuali (non un SAST): possono sfuggire o dare falsi positivi, e non dicono se una vulnerabilità di una libreria è raggiungibile dal codice.
- Le librerie copiate a mano sono riconosciute solo se la cartella ha nome e versione o se il file ha l'intestazione di una libreria nota (`KNOWN_JS` in `builtin_sbom.py`). Licenza, autore e impronta vengono dalla copia stessa, non dal registro; l'impronta di una cartella è lo SHA-256 dell'elenco ordinato "percorso + SHA-256 del file".
- "Non caricata" e "non usata direttamente" sono indizi testuali (nomi di funzione citati nell'advisory e cercati nei file caricati e nel codice del progetto): la libreria può chiamare la funzione al suo interno, quindi la vulnerabilità resta nel report e va verificata.
- Le licenze ricavate da deps.dev vengono scritte nella SBOM solo se l'ha generata il motore integrato; per le SBOM fornite o di Syft/Trivy restano in `risultati.json` (`registry_licenses`).
- I risultati valgono alla data del database di vulnerabilità (riportata nelle evidenze).
- OSV.dev, deps.dev, KEV, EPSS, Scorecard ed endoflife.date sono servizi esterni: con `--offline` l'analisi resta interamente locale.
- OSV.dev viene interrogato per i dettagli di al massimo 400 advisory: se sono di più, il report e le evidenze dicono quante restano senza gravità.
- OpenSSF Scorecard valuta il branch principale, non necessariamente la versione analizzata.
- Una SBOM generata da un rilascio vede ciò che è nei pacchetti, non ciò che l'installazione scarica o genera dopo: per quello serve analizzare anche il sistema installato (`sudo python3 analizza.py /opt/zimbra`).
- La tabella interna delle immagini fuori supporto va aggiornata nel tempo (online viene sostituita da endoflife.date).
- I segnali di provenienza (git, URL, hash mancanti) vengono dal motore integrato: Syft e Trivy non li riportano, e in quel caso restano solo i controlli sul repository e su deps.dev.
- `uv.lock` non distingue le dipendenze di sviluppo: vengono contate tutte.
- Il confronto con la SBOM del fornitore usa il nome del componente: nomi diversi per lo stesso pacchetto risultano come differenze da verificare a mano.
- SPDX RDF/XML viene validato se pubblicato nel repository, ma non è accettato come input: va convertito in SPDX JSON.
