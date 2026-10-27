"""Strutture dati condivise da tutti i moduli.

Perche' un modello comune: le SBOM arrivano in formati diversi (CycloneDX, SPDX).
Convertendole subito in questi oggetti, gli analizzatori lavorano su un solo formato
e non devono sapere da dove arrivano i dati.
"""

from dataclasses import dataclass, field


@dataclass
class Component:
    name: str
    version: str = ""
    purl: str = ""
    ecosystem: str = "sconosciuto"   # deb, java-archive, npm, python, binary...
    namespace: str = ""              # es. "ubuntu" in pkg:deb/ubuntu/..., groupId per maven
    supplier: str = ""               # fornitore / publisher / maintainer
    licenses: list = field(default_factory=list)
    cpes: list = field(default_factory=list)
    locations: list = field(default_factory=list)
    hashes: list = field(default_factory=list)
    ref: str = ""                    # identificativo interno alla SBOM (bom-ref / SPDXID)
    source_kind: str = ""            # provenienza dichiarata dal motore integrato: registry, git, locale,
                                     # altra fonte, artefatto; vuota se la SBOM non la riporta
    direct: object = None            # True = dipendenza diretta, False = indiretta, None = non noto
    dev: bool = False                # solo per sviluppo/test (scope "optional" in CycloneDX)
    hashable: bool = False           # voce di lockfile che dovrebbe avere un hash di integrita'
    license_source: str = ""         # "sbom" oppure "deps.dev" (licenza ricavata dal registro)
    registry: dict = field(default_factory=dict)  # dati di deps.dev: ultima versione, deprecazione...

    @property
    def key(self) -> str:
        """Chiave di confronto indipendente dalla versione (usata per duplicati e confronti)."""
        return f"{self.ecosystem}:{self.name}".lower()


@dataclass
class Sbom:
    fmt: str                         # "CycloneDX x.y" o "SPDX x.y"
    components: list
    timestamp: str = ""
    author_tools: list = field(default_factory=list)   # chi ha generato la SBOM
    subject: str = ""                # cosa descrive la SBOM (nome del software / sorgente)
    subject_version: str = ""        # versione dichiarata del software descritto
    subject_version_from: str = ""   # file da cui e' stata letta (motore integrato)
    has_dependencies: bool = False   # la SBOM contiene relazioni tra componenti?
    path: str = ""
    raw_count: int = 0               # voci prima di unire i duplicati identici
    notes: dict = field(default_factory=dict)  # note del motore integrato (file non letti, indici alternativi...)


@dataclass
class Vulnerability:
    id: str
    severity: str                    # Critical, High, Medium, Low, Negligible, Unknown
    component: str
    version: str
    ecosystem: str = ""
    fixed_in: list = field(default_factory=list)
    fix_state: str = "unknown"       # fixed, not-fixed, wont-fix, unknown
    cvss: float = 0.0
    epss: float = -1.0               # probabilita' di sfruttamento (0-1), -1 = non nota
    kev: bool = False                # presente nel catalogo CISA KEV (sfruttata davvero)
    aliases: list = field(default_factory=list)
    description: str = ""
    details: str = ""                # testo completo dell'advisory (OSV), per cercare le funzioni coinvolte
    reach: str = ""                  # "" = non valutata; "non caricata" / "non usata direttamente" (solo librerie
    reach_note: str = ""             # copiate nel repository, di cui il tool ha il codice)

    @property
    def cve_ids(self) -> list:
        ids = [self.id] + list(self.aliases)
        return [i for i in ids if i.upper().startswith("CVE-")]


# Ecosistemi in cui il purl implica un registro pubblico ufficiale: l'origine e' nota anche
# senza namespace (pkg:npm/lodash viene da registry.npmjs.org).
REGISTRY_ECOSYSTEMS = {"npm", "python", "java", "go", "rust", "ruby", "php", ".net", "perl"}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
SEVERITY_IT = {
    "Critical": "Critica", "High": "Alta", "Medium": "Media",
    "Low": "Bassa", "Negligible": "Trascurabile", "Unknown": "Non nota",
}
