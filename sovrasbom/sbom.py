"""Lettura delle SBOM: CycloneDX (JSON e XML) e SPDX (JSON e tag-value).

Perche' supportarle tutte: sono i formati usati dai fornitori.
Una PA riceve la SBOM nel formato che il fornitore sceglie, quindi il tool
deve accettarli e convertirli nel modello comune (model.Component).
XML e tag-value vengono prima tradotti nella stessa struttura del JSON, cosi' la
logica di lettura e' una sola. SPDX RDF/XML viene solo validato (inspect_file).
"""

import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import unquote

from .model import Component, Sbom


# --------------------------------------------------------------------------- purl
def parse_purl(purl: str) -> tuple:
    """Estrae (tipo, namespace) da un Package URL, es. pkg:deb/ubuntu/openssl@3.0 -> ("deb", "ubuntu").

    Il purl e' l'identificativo univoco di un pacchetto: dice da quale ecosistema
    arriva (deb, maven, npm...) e spesso chi lo distribuisce (namespace).
    """
    if not purl or not purl.startswith("pkg:"):
        return "", ""
    body = purl[4:].split("?")[0].split("#")[0].split("@")[0]
    parts = [unquote(p) for p in body.split("/") if p]
    ptype = parts[0] if parts else ""
    namespace = "/".join(parts[1:-1]) if len(parts) > 2 else ""
    return ptype, namespace


PURL_TO_ECOSYSTEM = {
    "deb": "deb", "rpm": "rpm", "apk": "apk", "maven": "java", "npm": "npm",
    "pypi": "python", "gem": "ruby", "golang": "go", "cargo": "rust", "nuget": ".net",
    "composer": "php", "generic": "binario", "github": "github", "cpan": "perl", "conan": "c/c++",
}

SYFT_TYPE_TO_ECOSYSTEM = {
    "java-archive": "java", "jenkins-plugin": "java", "binary": "binario", "python": "python",
    "npm": "npm", "go-module": "go", "deb": "deb", "rpm": "rpm", "perl": "perl",
    "gem": "ruby", "rust-crate": "rust", "php-composer": "php", "dotnet": ".net",
    "github-action": "github-action", "github-action-workflow": "github-action",
}


def _ecosystem(purl_type: str, syft_type: str) -> str:
    if syft_type and syft_type in SYFT_TYPE_TO_ECOSYSTEM:
        return SYFT_TYPE_TO_ECOSYSTEM[syft_type]
    if purl_type:
        return PURL_TO_ECOSYSTEM.get(purl_type, purl_type)
    return "sconosciuto"


# ------------------------------------------------------------------- CycloneDX
def _cdx_licenses(comp: dict) -> list:
    out = []
    for lic in comp.get("licenses", []) or []:
        if "expression" in lic:
            out.append(lic["expression"])
        elif "license" in lic:
            l = lic["license"]
            out.append(l.get("id") or l.get("name") or "")
    return [l for l in out if l]


def _cdx_supplier(comp: dict) -> str:
    sup = comp.get("supplier") or {}
    if isinstance(sup, dict) and sup.get("name"):
        return sup["name"]
    for k in ("publisher", "author"):
        if comp.get(k):
            return comp[k]
    authors = comp.get("authors") or []
    if authors and isinstance(authors[0], dict) and authors[0].get("name"):
        return authors[0]["name"]
    return ""


def _flatten_cdx(components: list) -> list:
    """CycloneDX puo' annidare componenti dentro altri componenti: li appiattiamo."""
    flat = []
    for c in components or []:
        flat.append(c)
        if c.get("components"):
            flat.extend(_flatten_cdx(c["components"]))
    return flat


def _parse_cyclonedx(doc: dict, path: str, fmt_suffix: str = "") -> Sbom:
    meta = doc.get("metadata", {}) or {}
    root_ref = (meta.get("component") or {}).get("bom-ref", "")
    deps = doc.get("dependencies") or []
    direct = next((set(d.get("dependsOn") or []) for d in deps if root_ref and d.get("ref") == root_ref), None)
    comps = []
    for c in _flatten_cdx(doc.get("components", [])):
        if c.get("type") in ("operating-system", "file", "container"):
            continue  # descrivono il contesto, non un componente software da valutare
        if c.get("type") == "application" and not c.get("purl"):
            continue  # es. Trivy elenca il file package-lock.json come "applicazione": e' il contenitore, non un pacchetto
        props = {}
        for p in c.get("properties", []) or []:
            props.setdefault(p.get("name"), p.get("value"))
        purl = c.get("purl", "")
        ptype, ns = parse_purl(purl)
        cpes = [c["cpe"]] if c.get("cpe") else []
        cpes += [v for k, v in props.items() if k and k.startswith("syft:cpe23")]
        locations = [v for k, v in props.items() if k and k.startswith("syft:location:") and k.endswith(":path")]
        ref = c.get("bom-ref", "")
        comps.append(Component(
            name=c.get("name", ""),
            version=c.get("version", "") or "",
            purl=purl,
            ecosystem=_ecosystem(ptype, props.get("syft:package:type", "")),
            namespace=ns,
            supplier=_cdx_supplier(c),
            licenses=_cdx_licenses(c),
            cpes=cpes,
            locations=locations,
            hashes=[h.get("content", "") for h in c.get("hashes", []) or []],
            ref=ref,
            source_kind=props.get("sovrasbom:source", "") or "",
            direct=(ref in direct) if direct is not None else None,
            dev=c.get("scope") in ("optional", "excluded"),
            hashable=props.get("sovrasbom:hashable") == "true",
            license_source="sbom" if c.get("licenses") else "",
        ))

    tools = meta.get("tools", {})
    tool_list = tools.get("components", []) if isinstance(tools, dict) else (tools or [])
    author_tools = [f"{t.get('name', '?')} {t.get('version', '')}".strip() for t in tool_list]
    notes = {}
    for p in meta.get("properties") or []:
        name = p.get("name") or ""
        if name.startswith("sovrasbom:note:"):
            notes.setdefault(name.split(":", 2)[2], []).append(p.get("value", ""))
    version_from = next((p.get("value", "") for p in meta.get("properties") or []
                         if p.get("name") == "sovrasbom:version-source"), "")
    return Sbom(
        fmt=f"CycloneDX {fmt_suffix}{doc.get('specVersion', '?')}",
        components=comps,
        timestamp=meta.get("timestamp", ""),
        author_tools=author_tools,
        subject=(meta.get("component") or {}).get("name", ""),
        subject_version=(meta.get("component") or {}).get("version", ""),
        subject_version_from=version_from,
        has_dependencies=any(d.get("dependsOn") for d in deps),
        path=path,
        notes=notes,
    )


def _local(e) -> str:
    return e.tag.split("}")[-1]


def _kids(e, name) -> list:
    return [c for c in e if _local(c) == name] if e is not None else []


def _kid(e, name):
    return next(iter(_kids(e, name)), None)


def _txt(e, name) -> str:
    k = _kid(e, name)
    return (k.text or "").strip() if k is not None else ""


def _cdx_xml_component(e) -> dict:
    c = {"type": e.get("type", "library"), "bom-ref": e.get("bom-ref", ""), "name": _txt(e, "name"),
         "version": _txt(e, "version"), "purl": _txt(e, "purl"), "cpe": _txt(e, "cpe"),
         "publisher": _txt(e, "publisher"), "author": _txt(e, "author"), "scope": _txt(e, "scope")}
    sup = _kid(e, "supplier")
    if sup is not None:
        c["supplier"] = {"name": _txt(sup, "name")}
    lics = []
    for l in _kids(_kid(e, "licenses"), "license"):
        lics.append({"license": {"id": _txt(l, "id"), "name": _txt(l, "name")}})
    for x in _kids(_kid(e, "licenses"), "expression"):
        lics.append({"expression": (x.text or "").strip()})
    c["licenses"] = lics
    c["hashes"] = [{"alg": h.get("alg", ""), "content": (h.text or "").strip()} for h in _kids(_kid(e, "hashes"), "hash")]
    c["properties"] = [{"name": p.get("name"), "value": (p.text or "").strip()}
                       for p in _kids(_kid(e, "properties"), "property")]
    c["components"] = [_cdx_xml_component(x) for x in _kids(_kid(e, "components"), "component")]
    return {k: v for k, v in c.items() if v not in ("", None)}


def cyclonedx_xml_to_dict(root) -> dict:
    """Traduce CycloneDX XML nella stessa struttura del JSON."""
    ns = root.tag[1:root.tag.find("}")] if root.tag.startswith("{") else ""
    meta_e = _kid(root, "metadata")
    tools = []
    for t in _kids(_kid(meta_e, "tools"), "tool"):
        tools.append({"name": _txt(t, "name"), "version": _txt(t, "version")})
    for t in _kids(_kid(_kid(meta_e, "tools"), "components"), "component"):
        tools.append({"name": _txt(t, "name"), "version": _txt(t, "version")})
    mc = _kid(meta_e, "component")
    meta = {"timestamp": _txt(meta_e, "timestamp"), "tools": tools,
            "component": {"name": _txt(mc, "name"), "bom-ref": mc.get("bom-ref", "")} if mc is not None else {},
            "properties": [{"name": p.get("name"), "value": (p.text or "").strip()}
                           for p in _kids(_kid(meta_e, "properties"), "property")]}
    deps = [{"ref": d.get("ref"), "dependsOn": [x.get("ref") for x in _kids(d, "dependency")]}
            for d in _kids(_kid(root, "dependencies"), "dependency")]
    return {"bomFormat": "CycloneDX", "specVersion": ns.rsplit("/", 1)[-1] if "cyclonedx.org" in ns else root.get("version", "?"),
            "metadata": meta, "components": [_cdx_xml_component(c) for c in _kids(_kid(root, "components"), "component")],
            "dependencies": deps}


# ------------------------------------------------------------------------ SPDX
def _spdx_clean(value) -> str:
    if not value or value in ("NOASSERTION", "NONE"):
        return ""
    return str(value)


def _parse_spdx(doc: dict, path: str, fmt_suffix: str = "") -> Sbom:
    rels = doc.get("relationships", []) or []
    packages = doc.get("packages", []) or []
    # Il pacchetto "descritto" dal documento e' il software stesso (es. myapp), non un suo componente:
    # contarlo gonfierebbe i numeri e creerebbe falsi "non dichiarati" nel confronto con il fornitore.
    described = set(doc.get("documentDescribes") or [])
    described |= {r.get("relatedSpdxElement") for r in rels
                  if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT"}
    described |= {r.get("spdxElementId") for r in rels
                  if r.get("relationshipType") == "DESCRIBED_BY" and r.get("relatedSpdxElement") == "SPDXRef-DOCUMENT"}
    if not any(p.get("SPDXID") not in described for p in packages):
        described = set()                       # il documento descrive un solo pacchetto: e' il componente
    direct = {r.get("relatedSpdxElement") for r in rels
              if r.get("relationshipType") == "DEPENDS_ON" and r.get("spdxElementId") in described}
    direct |= {r.get("spdxElementId") for r in rels
               if r.get("relationshipType") == "DEPENDENCY_OF" and r.get("relatedSpdxElement") in described}
    comps, subject = [], ""
    for p in packages:
        if p.get("SPDXID") in described:
            subject = subject or p.get("name", "")
            continue
        purl, cpes = "", []
        for ref in p.get("externalRefs", []) or []:
            rtype = ref.get("referenceType", "")
            if rtype == "purl":
                purl = ref.get("referenceLocator", "")
            elif rtype.startswith("cpe"):
                cpes.append(ref.get("referenceLocator", ""))
        ptype, ns = parse_purl(purl)
        lic = _spdx_clean(p.get("licenseConcluded")) or _spdx_clean(p.get("licenseDeclared"))
        supplier = _spdx_clean(p.get("supplier")) or _spdx_clean(p.get("originator"))
        supplier = supplier.replace("Organization:", "").replace("Person:", "").strip()
        comps.append(Component(
            name=p.get("name", ""),
            version=_spdx_clean(p.get("versionInfo")),
            purl=purl,
            ecosystem=_ecosystem(ptype, ""),
            namespace=ns,
            supplier=supplier,
            licenses=[lic] if lic else [],
            cpes=cpes,
            hashes=[c.get("checksumValue", "") for c in p.get("checksums", []) or []],
            ref=p.get("SPDXID", ""),
            direct=(p.get("SPDXID") in direct) if direct else None,
            license_source="sbom" if lic else "",
        ))
    info = doc.get("creationInfo", {}) or {}
    return Sbom(
        fmt=f"SPDX {fmt_suffix}{doc.get('spdxVersion', '?').replace('SPDX-', '')}",
        components=comps,
        timestamp=info.get("created", ""),
        author_tools=[c.replace("Tool:", "").strip() for c in info.get("creators", []) if c.startswith("Tool:")],
        subject=subject or doc.get("name", ""),
        has_dependencies=any(r.get("relationshipType") in ("DEPENDS_ON", "CONTAINS", "DEPENDENCY_OF") for r in rels),
        path=path,
    )


def spdx_tagvalue_to_dict(text: str) -> dict:
    """Traduce SPDX tag-value ("PackageName: x") nella stessa struttura del JSON."""
    doc = {"packages": [], "relationships": [], "creationInfo": {"creators": []}}
    pkg, lines, i = None, text.splitlines(), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        tag, _, val = line.partition(":")
        tag, val = tag.strip(), val.strip()
        if val.startswith("<text>"):                     # valore su piu' righe
            buf = val[6:]
            while "</text>" not in buf and i < len(lines):
                buf += "\n" + lines[i]
                i += 1
            val = buf.split("</text>")[0].strip()
        if tag == "SPDXVersion":
            doc["spdxVersion"] = val
        elif tag == "DocumentName":
            doc["name"] = val
        elif tag == "Created":
            doc["creationInfo"]["created"] = val
        elif tag == "Creator":
            doc["creationInfo"]["creators"].append(val)
        elif tag == "Relationship":
            parts = val.split()
            if len(parts) >= 3:
                doc["relationships"].append({"spdxElementId": parts[0], "relationshipType": parts[1],
                                             "relatedSpdxElement": parts[2]})
        elif tag == "PackageName":
            pkg = {"name": val, "externalRefs": [], "checksums": []}
            doc["packages"].append(pkg)
        elif tag in ("FileName", "SnippetSPDXID"):
            pkg = None                                   # da qui in poi descrive file, non pacchetti
        elif pkg is not None:
            if tag == "SPDXID":
                pkg["SPDXID"] = val
            elif tag == "PackageVersion":
                pkg["versionInfo"] = val
            elif tag == "PackageSupplier":
                pkg["supplier"] = val
            elif tag == "PackageOriginator":
                pkg["originator"] = val
            elif tag == "PackageLicenseConcluded":
                pkg["licenseConcluded"] = val
            elif tag == "PackageLicenseDeclared":
                pkg["licenseDeclared"] = val
            elif tag == "PackageChecksum":
                alg, _, value = val.partition(":")
                pkg["checksums"].append({"algorithm": alg.strip(), "checksumValue": value.strip()})
            elif tag == "ExternalRef":
                parts = val.split()
                if len(parts) >= 3:
                    pkg["externalRefs"].append({"referenceCategory": parts[0], "referenceType": parts[1],
                                                "referenceLocator": parts[2]})
    return doc


# ---------------------------------------------------------------------- entry
def _dedupe(sbom: Sbom) -> Sbom:
    """Unisce le voci identiche (stesso purl o stesso nome+versione+ecosistema).

    Perche': Syft elenca un'azione GitHub una volta per ogni workflow che la usa,
    e una libreria una volta per ogni percorso in cui compare. Contarle tutte
    gonfierebbe i numeri. I percorsi vengono conservati, uniti nella stessa voce.
    """
    merged = {}
    for c in sbom.components:
        key = c.purl.split("?")[0] if c.purl else f"{c.ecosystem}:{c.name}@{c.version}".lower()
        if key in merged:
            m = merged[key]
            m.locations = sorted(set(m.locations) | set(c.locations))
            m.licenses = m.licenses or c.licenses
            m.hashes = m.hashes or c.hashes
            m.supplier = m.supplier or c.supplier
            m.direct = True if (m.direct or c.direct) else (m.direct if m.direct is not None else c.direct)
        else:
            merged[key] = c
    sbom.raw_count = len(sbom.components)
    sbom.components = list(merged.values())
    return sbom


def detect_format(text: str) -> str:
    """'cdx-json', 'spdx-json', 'cdx-xml', 'spdx-rdf', 'spdx-tv' oppure '' se non e' una SBOM."""
    s = text.lstrip("﻿ \t\r\n")
    if s[:1] == "{":
        try:
            doc = json.loads(s)
        except ValueError:
            return ""
        if isinstance(doc, dict) and doc.get("bomFormat") == "CycloneDX":
            return "cdx-json"
        if isinstance(doc, dict) and "spdxVersion" in doc:
            return "spdx-json"
        return ""
    if s[:1] == "<":
        head = s[:4000]
        if re.search(r"<(\w+:)?bom[\s>]", head) and "cyclonedx" in head.lower():
            return "cdx-xml"
        if "spdx.org/rdf" in head or "SpdxDocument" in s[:20000]:
            return "spdx-rdf"
        return ""
    if re.search(r"(?m)^SPDXVersion:\s*SPDX-", s[:4000]):
        return "spdx-tv"
    return ""


def parse_text(text: str, path: str = "") -> Sbom:
    fmt = detect_format(text)
    s = text.lstrip("﻿ \t\r\n")
    if fmt == "cdx-json":
        return _dedupe(_parse_cyclonedx(json.loads(s), path))
    if fmt == "spdx-json":
        return _dedupe(_parse_spdx(json.loads(s), path))
    if fmt == "cdx-xml":
        return _dedupe(_parse_cyclonedx(cyclonedx_xml_to_dict(ET.fromstring(s)), path, "XML "))
    if fmt == "spdx-tv":
        return _dedupe(_parse_spdx(spdx_tagvalue_to_dict(s), path, "tag-value "))
    if fmt == "spdx-rdf":
        raise ValueError(f"{path}: SPDX RDF/XML non è supportato come input; convertilo in SPDX JSON "
                         "(es. con 'pyspdxtools -i file.rdf -o file.spdx.json')")
    raise ValueError(
        f"{path}: formato non riconosciuto. Sono supportati CycloneDX (JSON o XML) e SPDX (JSON o tag-value) "
        "(con syft: -o cyclonedx-json oppure -o spdx-json)."
    )


def read_text(path: str, limit: int = 200_000_000) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read(limit)


def load_sbom(path: str) -> Sbom:
    """Riconosce il formato dal contenuto (non dall'estensione) e lo converte."""
    return parse_text(read_text(path), path)


def looks_like_sbom(path: str) -> bool:
    if not path.lower().endswith((".json", ".xml", ".spdx", ".tv", ".txt", ".rdf")):
        return False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = fh.read(5_000_000)
    except OSError:
        return False
    return bool(detect_format(head))


# ------------------------------------------------------- SBOM pubblicate nel repo
def _rdf_inspect(text: str, label: str) -> dict:
    try:
        r = ET.fromstring(text)
    except ET.ParseError:
        return {"file": label, "valid": False, "format": "XML non valido"}
    items = [p for p in r.iter() if _local(p) == "Package"]
    ver = next((_txt(p, "spdxVersion") for p in r.iter() if _local(p) in ("SpdxDocument", "Document")
                and _txt(p, "spdxVersion")), "")
    fmt = f"SPDX RDF {ver}".strip()
    if not items:
        return {"file": label, "valid": False, "format": fmt + " ma senza pacchetti"}
    n_ver = sum(1 for p in items if _txt(p, "versionInfo"))
    n_purl = sum(1 for p in items if _txt(p, "versionInfo") and any(
        "purl" in ((c.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}resource") or "") + _txt(c, "referenceType"))
        for er in _kids(p, "externalRef") + _kids(p, "externalRefs") for c in er))
    n_lic = sum(1 for p in items if _txt(p, "licenseConcluded") not in ("", "NOASSERTION")
                or _txt(p, "licenseDeclared") not in ("", "NOASSERTION"))
    return {"file": label, "valid": True, "format": fmt, "components": len(items),
            "completeness": round((n_ver + n_purl + n_lic) / (3 * len(items)), 2)}


def inspect_text(text: str, label: str) -> dict:
    """Valida una SBOM e ne misura la completezza: quota media di versione, purl con versione e licenza."""
    fmt = detect_format(text)
    if not fmt:
        s = text.lstrip()
        kind = "JSON" if s[:1] in "{[" else "XML" if s[:1] == "<" else "testo"
        return {"file": label, "valid": False, "format": f"{kind} non riconosciuto come CycloneDX o SPDX"}
    if fmt == "spdx-rdf":
        return _rdf_inspect(text, label)
    try:
        sb = parse_text(text, label)
    except (ValueError, ET.ParseError) as exc:
        return {"file": label, "valid": False, "format": f"{fmt}: non leggibile ({str(exc)[:60]})"}
    comps = sb.components
    if not comps:
        return {"file": label, "valid": False, "format": f"{sb.fmt} ma senza componenti"}
    n_ver = sum(1 for c in comps if c.version)
    n_purl = sum(1 for c in comps if c.purl and c.version)
    n_lic = sum(1 for c in comps if c.licenses)
    return {"file": label, "valid": True, "format": sb.fmt, "components": len(comps),
            "completeness": round((n_ver + n_purl + n_lic) / (3 * len(comps)), 2)}
