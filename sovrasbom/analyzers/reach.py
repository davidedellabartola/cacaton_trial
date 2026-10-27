"""Le vulnerabilita' delle librerie copiate nel repository riguardano davvero il software?

Solo per le librerie copiate a mano (sovrasbom:source = copiato), di cui il tool ha il codice:
1. quali file della libreria il progetto carica davvero (riferimenti nei file del progetto:
   <include>, <script src>, import/require);
2. quali funzioni nomina l'advisory (`WordArray.random()`, PBKDF2...);
3. se la funzione e' definita solo in file mai caricati  -> "non caricata";
   se e' caricata ma il codice del progetto non la chiama -> "non usata direttamente".
E' un indizio, non una prova (la libreria puo' chiamarla al suo interno): la vulnerabilita'
resta nel report con la sua gravita', ma scende nell'ordine di intervento e pesa meno
sulla Sicurezza. Se l'advisory non nomina funzioni riconoscibili non si conclude nulla.
"""

import os
import re

# oggetti globali del linguaggio: compaiono negli advisory ma non sono funzioni della libreria
GLOBALS = ("Math.", "crypto.", "window.", "JSON.", "Date.", "Object.", "Array.", "String.", "Number.",
           "document.", "require(", "process.")
TEXT_EXT = (".js", ".ts", ".jsx", ".tsx", ".html", ".htm", ".xml", ".jsp", ".php", ".vue", ".json")


def _read(root, rel, limit=2_000_000):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def advisory_symbols(v, lib_name: str) -> list:
    """Funzioni nominate dall'advisory: `A.b.c()` -> "b.c"; nomi tipo PBKDF2 nel titolo."""
    text = f"{v.description}\n{v.details}"
    out = []
    for tok in re.findall(r"`([A-Za-z_$][\w$.]*)\(\)?`|`([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)`", text):
        tok = tok[0] or tok[1]
        if tok.startswith(GLOBALS) or tok.lower() in (lib_name.lower(), lib_name.lower().replace("-", "")):
            continue
        parts = tok.split(".")
        out.append(".".join(parts[-2:]) if len(parts) > 1 else parts[0])
    # algoritmi e funzioni nel titolo: PBKDF2, EvpKDF, SHA3... (lettere e cifre insieme)
    out += [w for w in re.findall(r"\b([A-Za-z]{2,}\d[A-Za-z0-9]*)\b", v.description)
            if not re.fullmatch(r"(CVE|GHSA|CWE|SHA1|MD5|TLS|SSL)\d*", w, re.I)]
    return list(dict.fromkeys(out))


def _defined_in(sym: str, text: str) -> bool:
    last = sym.split(".")[-1]
    return sym in text or re.search(r"\b" + re.escape(last) + r"\s*[:=]\s*(?:function|\w+\.extend|\()", text) is not None


def analyze(vulns: list, components: list, root: str, own_files: list) -> dict:
    """Annota vulns (campi reach/reach_note) e restituisce i file caricati per ogni libreria copiata."""
    if not root:
        return {}
    copied = {(c.name, c.version): c for c in components if c.source_kind == "copiato" and c.locations}
    usage = {}
    own_text = {p: _read(root, p) for p in own_files if p.lower().endswith(TEXT_EXT)}
    for (name, version), c in copied.items():
        loc = c.locations[0]
        base = loc if os.path.isdir(os.path.join(root, loc)) else os.path.dirname(loc)
        lib_files = []
        for dp, _, fn in os.walk(os.path.join(root, base)):
            lib_files += [os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/") for f in fn]
        lib_files = [p for p in lib_files if p.endswith(".js")]
        # un file e' caricato se un file del progetto ne cita il percorso (almeno cartella/nome)
        loaded = []
        for p in lib_files:
            tail = "/".join(p.split("/")[-2:])
            if any(tail in t for t in own_text.values()):
                loaded.append(p)
        usage[name] = {"files": len(lib_files), "loaded": loaded}
        if not loaded:
            continue                       # non sappiamo come viene caricata: nessuna conclusione
        loaded_text = "\n".join(_read(root, p) for p in loaded)
        project_code = "\n".join(t for p, t in own_text.items() if p.lower().endswith((".js", ".ts", ".jsx", ".tsx")))
        for v in vulns:
            if (v.component, v.version) != (name, version):
                continue
            syms = advisory_symbols(v, name)
            if not syms:
                continue
            if not any(_defined_in(s, loaded_text) for s in syms):
                v.reach = "non caricata"
                v.reach_note = (f"{', '.join(syms[:2])} non è nei {len(loaded)} file della libreria "
                                f"caricati dal progetto")
            elif not any(s in project_code for s in syms):
                v.reach = "non usata direttamente"
                v.reach_note = (f"{', '.join(syms[:2])} è caricata ma il codice del progetto non la chiama "
                                "(potrebbe usarla la libreria stessa)")
    return usage
