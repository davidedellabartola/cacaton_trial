"""Segnali nel codice del progetto: cio' che la SBOM non puo' dire.

Controlli testuali, volutamente semplici e dichiarati (non sostituiscono una revisione
del codice ne' un SAST):
- crittografia debole: DES/3DES, RC4, modalita' ECB, MD5/SHA-1 usati per cifrare o firmare
- segreti nei file di configurazione (passphrase, password, chiavi) e, se il codice
  JavaScript li legge, segreti che finiscono nel browser di ogni utente
- credenziali messe nell'indirizzo (?pwd=..., &password=...): restano in cronologia e log
- servizi esterni: indirizzi https nei file di configurazione e nelle stringhe del codice,
  cioe' i fornitori da cui il software dipende mentre funziona (esclusi link e namespace XML)
- parametri della richiesta HTTP usati per costruire un indirizzo (SSRF) o un percorso di file
  (path traversal), anche attraverso una variabile intermedia; connessioni in HTTP non cifrato
- proxy o CORS aperti a qualsiasi dominio nella configurazione (allowedDomains = *)
Il codice di terzi copiato (vendor/, lib/<nome versione>, .min.js) e' escluso: ha i suoi controlli.
Informativo: non entra nell'indice di sovranita', ma produce raccomandazioni.
"""

import os
import re
import urllib.parse

from ..builtin_sbom import JS_BANNER_RE, list_files, vendored_dirs

SOURCE_EXT = (".js", ".ts", ".jsx", ".tsx", ".java", ".jsp", ".jspx", ".py", ".php", ".rb", ".cs", ".aspx", ".go",
              ".kt", ".c", ".cpp", ".h")
CONFIG_EXT = (".xml", ".properties", ".yml", ".yaml", ".json", ".ini", ".conf", ".cfg", ".toml", ".env")
CONFIG_SKIP = ("package.json", "package-lock.json", "composer.json", "tsconfig.json", "pom.xml")
WEAK_CRYPTO = [
    ("3DES/TripleDES", re.compile(r"\b(TripleDES|DESede|3DES|des-ede3)\b", re.I)),
    ("DES", re.compile(r"(CryptoJS\.DES\.|Cipher\.getInstance\(\s*\"DES[\"/]|\bDES\.new\(|createCipheriv?\(\s*['\"]des['\"-])")),
    ("RC4", re.compile(r"\b(RC4|ARCFOUR)\b")),
    ("modalità ECB", re.compile(r"(mode\.ECB|/ECB/|MODE_ECB|\becb\b['\"])", re.I)),
    ("MD5", re.compile(r"(CryptoJS\.MD5|MessageDigest\.getInstance\(\s*\"MD5|hashlib\.md5|\bmd5\()", re.I)),
]
SECRET_KEY = r"[\w.\-]*(?:passphrase|password|passwd|secret|api[_-]?key|private[_-]?key|token)[\w.\-]*"
# <property name="x_passphrase">valore</property>   oppure   x.password = valore   oppure  "secret": "valore"
SECRET_RES = [re.compile(r"name\s*=\s*\"(" + SECRET_KEY + r")\"[^>]*>\s*([^<\s][^<]*)<", re.I),
              re.compile(r"(?m)^\s*(" + SECRET_KEY + r")\s*[=:]\s*['\"]?([^'\"\s#]+)", re.I),
              re.compile(r"\"(" + SECRET_KEY + r")\"\s*:\s*\"([^\"]+)\"", re.I)]
URL_IN_QUERY = re.compile(r"[?&\"'](pwd|password|passwd|pass)=\"?\s*\+", re.I)
URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s\"'<>)]*)?")
# indirizzi che compaiono in licenze, schemi e documentazione: non sono servizi contattati
NOT_SERVICES = ("www.w3.org", "w3.org", "schemas.", "xmlns", "www.gnu.org", "gnu.org", "fsf.org", "opensource.org",
                "apache.org/licenses", "creativecommons.org", "example.com", "example.org", "localhost", "127.0.0.1",
                "zimbra.com/license", "json-schema.org", "spdx.org", "github.com", "code.google.com")
MAX_FILES = 4000
# valori presi dalla richiesta HTTP (Java/JSP, PHP, Python)
REQUEST_VAR_RES = [re.compile(r"(\w+)\s*=\s*(?:\(\s*String\s*\)\s*)?request\.getParameter\("),
                   re.compile(r"\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST)\["),
                   re.compile(r"(\w+)\s*=\s*request\.(?:args|form|values|GET|POST)(?:\.get\(|\[)")]
URL_SINK = re.compile(r"[\"']https?://[\"']|new URL\(|openConnection|Http(?:Get|Post|Put)\(|Rest\.invoke|curl_init|"
                      r"file_get_contents|requests\.(?:get|post)|urlopen|fetch\(")
PATH_SINK = re.compile(r"new File\(|File(?:Input|Output)Stream\(|FileReader\(|Paths\.get\(|fopen\(|[\"']/tmp/|"
                       r"readFile|unlink\(|\binclude\s*\(|\brequire\s*\(|open\(")
PLAIN_HTTP = re.compile(r"[\"']http://[\"']\s*(?:\.concat\(|\+|\.)|f[\"']http://\{")
# proxy o CORS che accettano qualsiasi dominio
OPEN_PROXY = re.compile(r"name\s*=\s*\"((?:allowed|proxy)\w*(?:domain|host|origin)s?|[\w.]*cors[\w.]*)\"[^>]*>\s*\*\s*<"
                        r"|^\s*((?:allowed|proxy)[\w.]*(?:domain|host|origin)s?|[\w.]*cors[\w.]*origin\w*)\s*[=:]\s*['\"]?\*",
                        re.I | re.M)


def _request_flows(text):
    """Righe in cui un parametro della richiesta (anche passato da una variabile) diventa indirizzo o percorso."""
    tainted = {m.group(1) for rx in REQUEST_VAR_RES for m in rx.finditer(text)}
    ssrf, traversal = [], []
    if not tainted:
        return ssrf, traversal, tainted
    lines = text.splitlines()
    # un passo di propagazione: x = "http://".concat(server)  ->  x e' anch'esso controllato da chi chiama
    for line in lines:
        m = re.match(r"\s*(?:[\w<>\[\]]+\s+)?\$?(\w+)\s*=\s*(.+)", line)
        if m and m.group(1) not in tainted and any(re.search(r"\b" + re.escape(t) + r"\b", m.group(2))
                                                   for t in tainted):
            tainted.add(m.group(1))
    for i, line in enumerate(lines, 1):
        code = line.strip()
        if code.startswith(("//", "#", "*", "/*")) or "getParameter(" in line:
            continue
        if not any(re.search(r"\b" + re.escape(t) + r"\b", line) for t in tainted):
            continue
        if URL_SINK.search(line):
            ssrf.append(i)
        if PATH_SINK.search(line):
            traversal.append(i)
    return ssrf, traversal, tainted


def _read(root, rel, limit=400_000):
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _by_line(where):
    path, _, line = where.rpartition(":")
    return (path, int(line) if line.isdigit() else 0)


def _is_service(url):
    host = urllib.parse.urlsplit(url).hostname or ""
    return bool(host) and "." in host and not any(x in url for x in NOT_SERVICES)


def own_files(root: str) -> list:
    """File del progetto: esclusi codice di terzi copiato, file minificati, test e documentazione."""
    files = list_files(root)
    vendored = tuple(d + "/" for d in vendored_dirs(files))
    return [p for p in files if not p.startswith(vendored) and not re.search(r"[.-]min\.js$", p)
            and not re.search(r"(^|/)(test|tests|spec|__tests__|docs?)/", p)][:MAX_FILES]


def analyze(root: str) -> dict:
    if not root:
        return {"applicable": False}
    own = own_files(root)
    sources = [p for p in own if p.lower().endswith(SOURCE_EXT)]
    # i file di traduzione (messages_it.properties, x_en_US.properties) contengono etichette, non valori
    # anche il file predefinito (x.properties accanto a x_it.properties) e' una traduzione
    bundles = {re.sub(r"_[a-z]{2}(_[A-Z]{2})?\.properties$", "", p) for p in own
               if re.search(r"_[a-z]{2}(_[A-Z]{2})?\.properties$", p)}
    configs = [p for p in own if p.lower().endswith(CONFIG_EXT) and p.rsplit("/", 1)[-1] not in CONFIG_SKIP
               and not re.search(r"(_[a-z]{2}(_[A-Z]{2})?|messages?|strings|i18n)\.properties$", p)
               and not (p.endswith(".properties") and p[:-len(".properties")] in bundles)]

    weak, cred_url, endpoints, secrets, links = {}, [], {}, [], set()
    ssrf, traversal, plain_http, open_proxy, cred_plain = [], [], [], [], []
    texts = {}
    for p in sources:
        text = _read(root, p)
        if JS_BANNER_RE.match(text[:400]):               # libreria nota copiata: non e' codice del progetto
            continue
        texts[p] = text
        s_lines, t_lines, tainted = _request_flows(text)
        ssrf += [f"{p}:{i}" for i in s_lines]
        traversal += [f"{p}:{i}" for i in t_lines]
        has_cred = any(re.search(r"pass|pwd", t, re.I) for t in tainted)
        for i, line in enumerate(text.splitlines(), 1):
            code = line.strip()
            if code.startswith(("//", "#", "*", "/*")):
                continue
            for label, rx in WEAK_CRYPTO:
                if rx.search(line):
                    weak.setdefault(label, []).append(f"{p}:{i}")
            if URL_IN_QUERY.search(line):
                cred_url.append(f"{p}:{i}")
            if PLAIN_HTTP.search(line):
                (cred_plain if has_cred else plain_http).append(f"{p}:{i}")
            for m in re.finditer(r"['\"](https?://[^'\"\s]+)['\"]", line):
                # un link mostrato all'utente (<a href=...>) non e' un servizio che il software contatta
                if re.search(r"href\s*=\s*\\?$", line[:m.start()].rstrip()):
                    links.add(urllib.parse.urlsplit(m.group(1)).hostname)
                    continue
                # namespace XML (xmlns, namespace = "http://..."): un nome, non un indirizzo contattato
                if re.search(r"xmlns|namespace", line, re.I):
                    continue
                if _is_service(m.group(1)):
                    endpoints.setdefault(urllib.parse.urlsplit(m.group(1)).hostname, []).append(f"{p}:{i}")
    for p in configs:
        text = _read(root, p, 200_000)
        for m in OPEN_PROXY.finditer(text):
            open_proxy.append(f"{p}: {m.group(1) or m.group(2)} = *")
        for m in URL_RE.finditer(text):
            if re.search(r"(xmlns(:\w+)?|namespace|schemaLocation)\s*=\s*[\"']?\s*$", text[max(0, m.start() - 40):m.start()]):
                continue
            if _is_service(m.group(0)):
                endpoints.setdefault(urllib.parse.urlsplit(m.group(0)).hostname, []).append(p)
        for rx in SECRET_RES:
            for m in rx.finditer(text):
                key, value = m.group(1), m.group(2).strip()
                if len(value) < 3 or value.startswith(("${", "%(", "{{", "$")) or value.lower() in ("true", "false"):
                    continue
                if value.lower() == key.lower().rsplit(".", 1)[-1].lower():     # etichetta: Password = Password
                    continue
                # il segreto e' letto dal codice che gira nel browser? (JavaScript del progetto)
                in_browser = sorted(s for s, t in texts.items() if s.lower().endswith((".js", ".ts")) and key in t)
                secrets.append({"key": key, "file": p, "browser": in_browser[:3],
                                "placeholder": bool(re.search(r"insert|inserire|change|changeme|xxx|your", value, re.I))})
    findings = []
    if weak:
        findings.append(("Alta", "Crittografia debole: " + ", ".join(sorted(weak)),
                         sorted({w for ws in weak.values() for w in ws}, key=_by_line)))
    if cred_url:
        findings.append(("Alta", "Credenziali inserite nell'indirizzo (restano in cronologia e nei log)", cred_url))
    if ssrf:
        findings.append(("Alta", "Indirizzo costruito con un parametro della richiesta (SSRF: il server contatta "
                                 "ciò che sceglie chi chiama)", ssrf))
    if traversal:
        findings.append(("Alta", "Percorso di file costruito con un parametro della richiesta (path traversal)",
                         traversal))
    if open_proxy:
        findings.append(("Alta", "Proxy o CORS aperto a qualsiasi dominio nella configurazione", open_proxy))
    if cred_plain:
        findings.append(("Alta", "Credenziali inviate in HTTP non cifrato", cred_plain))
    if plain_http:
        findings.append(("Media", "Connessioni in HTTP non cifrato costruite nel codice", plain_http))
    browser = [s for s in secrets if s["browser"]]
    if browser:
        findings.append(("Alta", "Segreto della configurazione letto dal codice nel browser (lo vede ogni utente)",
                         [f"{s['key']} ({s['file']} → {', '.join(s['browser'])})" for s in browser]))
    other = [s for s in secrets if not s["browser"]]
    if other:
        findings.append(("Media", "Segreti nei file di configurazione del repository",
                         [f"{s['key']} ({s['file']})" + (" — segnaposto" if s["placeholder"] else "") for s in other]))
    findings.sort(key=lambda f: f[0] != "Alta")
    return {
        "applicable": bool(sources or configs),
        "files": len(sources) + len(configs),
        "findings": [{"severity": s, "title": t, "where": w[:20], "count": len(w)} for s, t, w in findings],
        "weak_crypto": sorted(weak),
        "credentials_in_url": len(cred_url),
        "request_flows": len(ssrf) + len(traversal),
        "secrets": secrets,
        "endpoints": [{"host": h, "where": sorted(set(w))[:5]} for h, w in sorted(endpoints.items())],
        "links": sorted(h for h in links if h and h not in endpoints),
    }
