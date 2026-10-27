import json
import os

import pytest

from conftest import write_tree

from sovrasbom import builtin_sbom
from sovrasbom.analyzers import pipeline, run_all
from sovrasbom.analyzers.vulns import cvss4_score, load_osv, osv_missing_details
from sovrasbom.sbom import load_sbom
from sovrasbom.target import resolve


def _analyze(root, tmp_path):
    out = str(tmp_path / "sbom.cdx.json")
    builtin_sbom.generate(root, "myapp", out)
    target = resolve(root, log=lambda m: None)
    return run_all(load_sbom(out), None, None, target=target, online=False,
                   context={"sbom_engine": "integrato", "offline": True, "depsdev": None})


def test_opaque_provenance_lowers_traceability(test_repo, tmp_path):
    f = _analyze(test_repo, tmp_path)
    assert f["sovereignty"]["dimensions"]["Tracciabilità"] < 100
    titles = " | ".join(x["title"] for x in f["provenance"]["flags"])
    assert "fonti non ufficiali" in titles
    assert "Indici dei pacchetti alternativi" in titles
    assert "Codice di terzi copiato" in titles
    assert any("build.gradle" in u for u in f["provenance"]["unsupported"])


def test_license_recommendation_blames_the_engine_not_the_software(test_repo, tmp_path):
    f = _analyze(test_repo, tmp_path)
    titles = [t for _, t, _ in f["recommendations"]]
    assert "Chiarire le licenze mancanti" not in titles
    assert "Completare il dato sulle licenze" in titles


def test_governance_new_signals(test_repo, tmp_path):
    f = _analyze(test_repo, tmp_path)
    gv = f["governance"]
    labels = {s["label"]: s for s in gv["signals"]}
    assert gv["license"] == "MIT" and gv["license_osi"]
    assert labels["Strategia di uscita: esportazione e migrazione dei dati documentate"]["ok"] is True
    assert labels["Codice di condotta (CODE_OF_CONDUCT)"]["ok"] is False
    assert labels["Di un'organizzazione, non di un singolo utente"]["ok"] is None   # offline: non verificabile


def test_project_license_from_manifest(tmp_path):
    root = write_tree(tmp_path / "p", {"package.json": {"name": "x", "license": "EUPL-1.2"}, "README.md": "x"})
    f = _analyze(root, tmp_path)
    assert f["governance"]["license"] == "EUPL-1.2"


def test_pipeline_checks(test_repo):
    p = pipeline.analyze(test_repo, online=False)
    kinds = {x["kind"]: x for x in p["findings"]}
    assert kinds["pull_request_target"]["severity"] == "Alta"
    assert kinds["iniezione di comandi"]["where"].endswith(":16")
    assert "permessi non dichiarati" in kinds
    assert "base fuori supporto" in kinds                         # python:3.9
    assert not any("evil/commented" in x["text"] for x in p["findings"])
    assert p["actions_total"] == 2


def test_cvss4_and_osv_truncation(tmp_path):
    pytest.importorskip("cvss")
    assert cvss4_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") == 9.3
    doc = {"engine": "osv", "matches": [
        {"component": "a", "version": "1", "id": "GHSA-1", "detail": {
            "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}},
        {"component": "b", "version": "1", "id": "GHSA-2", "detail": None}]}
    vulns = {v.id: v for v in load_osv(doc)}
    assert vulns["GHSA-1"].severity == "Critical" and vulns["GHSA-2"].severity == "Unknown"
    path = tmp_path / "osv.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    assert osv_missing_details(str(path)) == (1, 2)


def test_cli_two_inputs_markdown_and_last_commit(test_repo, tmp_path, monkeypatch):
    pytest.importorskip("pptx")
    from sovrasbom.cli import main
    other = write_tree(tmp_path / "other", {"requirements.txt": "flask==3.0.0\n", "README.md": "x"})
    monkeypatch.chdir(tmp_path)
    md = str(tmp_path / "confronto.md")
    code = main([test_repo, other, "--offline", "--engine", "integrato", "--no-vulns", "--md", md,
                 "--last-commit", "2026-09-30", "--out", str(tmp_path / "out")])
    assert code == 0
    text = open(md, encoding="utf-8").read()
    assert "## Confronto" in text and "myapp" in text and "other" in text
    dirs = os.listdir(tmp_path / "out")
    assert len(dirs) == 2
    for d in dirs:
        files = os.listdir(tmp_path / "out" / d)
        assert {"report.md", "risultati.json", "SHA256SUMS", "evidenze.json"} <= set(files)
        assert any(x.endswith(".pptx") for x in files)
    res = json.load(open(tmp_path / "out" / dirs[0] / "risultati.json", encoding="utf-8"))
    active = next(s for s in res["governance"]["signals"] if s["label"].startswith("Attivo"))
    assert active["ok"] is True


ZIMLET_LIKE = {
    "README.md": "Zimlet: insert a passphrase into config_template.xml.",
    "LICENSE.txt": ("NOTE: SUPPLEMENTED TERMS\nAccording to sec. 7 of the GNU Affero General Public License, "
                    "version 3, the terms are supplemented: if you propagate the Program you are required not to "
                    "change his name; the Appropriate Legal Notices must show the logo of the author.\n\n"
                    "GNU AFFERO GENERAL PUBLIC LICENSE\nCopyright (C) 2007 Free Software Foundation, Inc.\n"),
    "z/app.js": ("/*\n * Version: ZPL 1.1\n * The contents of this file are subject to the Zimbra Public License\n"
                 " * Version 1.1 (\"License\")\n */\n"
                 "var pass = this.getConfig(\"z_passphrase\");\n"
                 "var opt = { mode: CryptoJS.mode.ECB };\n"
                 "var enc = CryptoJS.TripleDES.encrypt(msg, key, opt);\n"
                 "var q = \"login=\" + user + \"&pwd=\" + pwd;\n"
                 "window.open(\"https://webmail.example-pec.it/sso?\" + q);\n"),
    "z/config_template.xml": ("<zimletConfig><global>"
                              "<property name=\"z_host\">https://webmail.example-pec.it</property>"
                              "<property name=\"z_passphrase\">insert here a correct passphrase</property>"
                              "</global></zimletConfig>"),
    "z/z_it.properties": "pecPassword = Password PEC\n",           # etichetta tradotta, non un segreto
    "z/lib/CryptoJS v3.1.2/rollups/tripledes.js": "/*\nCryptoJS v3.1.2\n*/\nvar CryptoJS; TripleDES; RC4;",
}


def test_code_signals_and_license_terms_on_a_zimlet(tmp_path):
    root = write_tree(tmp_path / "zimlet", ZIMLET_LIKE)
    f = _analyze(root, tmp_path)
    cd = f["code"]
    titles = " | ".join(x["title"] for x in cd["findings"])
    assert "3DES/TripleDES" in titles and "modalità ECB" in titles and "RC4" not in titles   # libreria esclusa
    assert "Credenziali inserite nell'indirizzo" in titles
    assert [s["key"] for s in cd["secrets"]] == ["z_passphrase"] and cd["secrets"][0]["browser"]
    assert [e["host"] for e in cd["endpoints"]] == ["webmail.example-pec.it"]
    gv = f["governance"]
    assert "nome e marchi" in gv["license_extra_terms"] and "logo" in gv["license_extra_terms"]
    assert list(gv["license_conflicts"]) == ["Zimbra-1.1"]
    assert {c.name for c in load_sbom(str(tmp_path / "sbom.cdx.json")).components} == {"crypto-js"}
    recs = [t for _, t, _ in f["recommendations"]]
    assert "Chiarire la licenza del progetto" in recs
    assert "Verificare i servizi esterni da cui dipende il software" in recs


def test_plain_gpl_license_has_no_extra_terms(tmp_path):
    from sovrasbom.analyzers.governance import license_extra_terms
    root = write_tree(tmp_path / "gpl", {"LICENSE": "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November "
                                         "2007\nCopyright (C) 2007 Free Software Foundation, Inc.\n7. Additional "
                                         "Terms. ..."})
    assert license_extra_terms(root, "LICENSE") == ""


def test_index_not_classified_with_few_dimensions(tmp_path):
    root = write_tree(tmp_path / "docs-only", {"README.md": "x", "LICENSE": "MIT License\nPermission is hereby "
                                               "granted, free of charge"})
    sov = _analyze(root, tmp_path)["sovereignty"]
    assert sov["measured"] < 3 and not sov["classified"] and sov["level"] == "Non classificabile"


def test_copied_library_reachability_and_single_recommendation(tmp_path):
    from sovrasbom.model import Vulnerability
    files = dict(ZIMLET_LIKE)
    files["z/zimlet.xml"] = ('<zimlet name="z" version="2.0"><include>app.js</include>'
                             '<include>lib/CryptoJS v3.1.2/rollups/tripledes.js</include></zimlet>')
    files["z/lib/CryptoJS v3.1.2/rollups/tripledes.js"] = (
        "/*\nCryptoJS v3.1.2\ncode.google.com/p/crypto-js/wiki/License\n(c) 2009-2013 by Jeff Mott. All rights reserved.\n*/"
        "\nvar W=n.WordArray=s.extend({random:function(a){return Math.random()}});")
    files["z/lib/CryptoJS v3.1.2/components/pbkdf2.js"] = "C.PBKDF2=function(){};"
    root = write_tree(tmp_path / "zimlet", files)
    out = str(tmp_path / "sbom.cdx.json")
    builtin_sbom.generate(root, "z", out)
    sbom = load_sbom(out)
    (c,) = sbom.components
    assert (c.licenses, c.supplier, len(c.hashes)) == (["BSD-3-Clause"], "Jeff Mott", 1)
    assert sbom.subject_version == "2.0"
    vulns = [Vulnerability("GHSA-pbkdf2", "Critical", "crypto-js", "3.1.2", fixed_in=["4.2.0"], fix_state="fixed",
                           description="crypto-js PBKDF2 1,000 times weaker"),
             Vulnerability("GHSA-random", "Critical", "crypto-js", "3.1.2", fixed_in=["4.0.0"], fix_state="fixed",
                           description="weak random", details="`CryptoJS.lib.WordArray.random()` uses `Math.random()`")]
    f = run_all(sbom, vulns, None, target=resolve(root, log=lambda m: None), online=False,
                context={"sbom_engine": "integrato", "offline": True, "depsdev": None})
    assert {v.id: v.reach for v in vulns} == {"GHSA-pbkdf2": "non caricata", "GHSA-random": "non usata direttamente"}
    titles = [t for _, t, _ in f["recommendations"]]
    assert "Applicare gli aggiornamenti disponibili" not in titles        # aggiornare non e' la correzione
    assert sum(1 for t in titles if "crypto-js" in t or "copiato" in t) == 1
    assert "Ottenere ciò che oggi va chiesto al fornitore" not in titles  # ZIMLET_LIKE non lo dice
    assert f["sovereignty"]["dimensions"]["Sicurezza"] < 70               # i segnali gravi nel codice pesano


def test_nested_package_compared_with_sources(tmp_path):
    import zipfile
    root = write_tree(tmp_path / "pkg", {"README.md": "Ask us for the license key.", "app/a.js": "1",
                                         "app/b.js": "2"})
    with zipfile.ZipFile(os.path.join(root, "app.zip"), "w") as z:
        z.writestr("a.js", "1")
        z.writestr("b.js", "CAMBIATO")
        z.writestr("lib/jquery.js", "/*! jQuery v1.8.3 | jquery.org/license */")
    deps, notes = builtin_sbom.collect(root)
    assert notes["nested"] == ["app.zip;diverso;rispetto a app/: 1 file diversi, 1 solo nel pacchetto (es. b.js)"]
    assert [(d["name"], d["version"], d["location"], d["license"]) for d in deps] == [
        ("jquery", "1.8.3", "app.zip!/lib/jquery.js", "MIT")]
    f = _analyze(root, tmp_path)
    assert any(x["title"].startswith("Pacchetto da installare diverso") for x in f["provenance"]["flags"])
    assert f["governance"]["exit"]["from_vendor"]


def _jar(entries: dict) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_java_webapp_like_processmaker(tmp_path):
    jsp = ('<%\nString nameFile=(String)request.getParameter("nameFile");\n'
           'String pathFile="/tmp/".concat(nameFile);\n'
           'String password = (String)request.getParameter("openBravoPassword");\n'
           'String server = (String)request.getParameter("openBravoUrl");\n'
           'String strUrl = "http://".concat(server);\n'
           'String namespace = "http://www.processmaker.com";\n'
           'File pdfFile = new File(pathFile);\n'
           'result = Rest.invoke(GET, strUrl, null, null, user, password);\n%>\n')
    root = write_tree(tmp_path / "pm", {
        "README.md": "x", "app/JSP/invokeRest.jsp": jsp,
        "LICENSE": "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n",
        "app/app.properties": "Password = Password\n", "app/app_it.properties": "Password = Password\n",
        "app/api.js": 'this.xmlNs = "http://processmaker.com";\nvar p = getConfig("Password");',
        "app/config_template.xml": '<zimletConfig><global><property name="allowedDomains">*</property>'
                                   '</global></zimletConfig>'})
    with open(os.path.join(root, "app", "InvokeMethods.jar"), "wb") as fh:
        fh.write(_jar({"META-INF/maven/org.apache.pdfbox/pdfbox/pom.properties":
                       "groupId=org.apache.pdfbox\nartifactId=pdfbox\nversion=1.7.1\n",
                       "org/apache/pdfbox/PDF.class": "", "junit/framework/Assert.class": "",
                       "org/junit/Test.class": "", "org/json/XML.class": "",
                       "it/seacom/invoke/Rest.class": "", "it/seacom/pdf/Parser.class": ""}))
    with open(os.path.join(root, "app", "httpclient-cache-4.2.1.jar"), "wb") as fh:
        fh.write(_jar({"META-INF/maven/org.apache.httpcomponents/httpclient-cache/pom.properties":
                       "groupId=org.apache.httpcomponents\nartifactId=httpclient-cache\nversion=4.2.1\n",
                       "META-INF/LICENSE.txt": "Apache License\nVersion 2.0, January 2004\n",
                       "org/apache/http/impl/client/cache/Cache.class": ""}))
    f = _analyze(root, tmp_path)
    comps = {c.name: c for c in load_sbom(str(tmp_path / "sbom.cdx.json")).components}
    assert set(comps) == {"org.apache.pdfbox:pdfbox", "junit:junit", "org.json:json",
                          "org.apache.httpcomponents:httpclient-cache"}     # niente httpclient fantasma
    assert comps["org.apache.httpcomponents:httpclient-cache"].licenses == ["Apache-2.0"]
    assert comps["junit:junit"].licenses == ["EPL-1.0"] and not comps["junit:junit"].version
    titles = " | ".join(x["title"] for x in f["provenance"]["flags"])
    assert "Codice compilato senza sorgenti" in titles
    code = " | ".join(x["title"] for x in f["code"]["findings"])
    assert "SSRF" in code and "path traversal" in code and "allowedDomains" not in code
    assert "Proxy o CORS aperto" in code and "Credenziali inviate in HTTP" in code
    assert not f["code"]["secrets"] and not f["code"]["endpoints"]                 # etichette e namespace
    compat = " | ".join(x["message"] for x in f["licenses"]["compatibility"])
    assert "EPL-1.0 è incompatibile" in compat
    assert "Chiedere i sorgenti del codice compilato" in [t for _, t, _ in f["recommendations"]]
