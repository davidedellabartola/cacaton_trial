import json

import pytest
from conftest import write_tree

from sovrasbom import builtin_sbom
from sovrasbom.sbom import load_sbom


def _generate(root, tmp_path):
    out = str(tmp_path / "sbom.cdx.json")
    builtin_sbom.generate(root, "myapp", out)
    with open(out, encoding="utf-8") as fh:
        return out, json.load(fh)


def test_parsers_find_all_components(test_repo, tmp_path):
    out, doc = _generate(test_repo, tmp_path)
    names = {(c["name"], c.get("version")) for c in doc["components"]}
    for expected in [("lodash", "4.17.21"), ("evil", "1.0.0"), ("requests", "2.31.0"), ("editable", None),
                     ("localpkg", None), ("zlib", "1.3.1"), ("openssl", None), ("fmt", "10.2.1"),
                     ("cmake", "3.27.0"), ("Newtonsoft.Json", "13.0.3"),
                     ("org.slf4j:slf4j-api", "2.0.9"),               # versione da dependencyManagement
                     ("com.google.guava:guava", "33.0.0-jre")]:
        assert expected in names, expected
    sb = load_sbom(out)
    notes = sb.notes
    assert any("build.gradle" in n for n in notes["unsupported"])
    assert any("extra-index-url" in n for n in notes["index_urls"])
    kinds = {c.name: c.source_kind for c in sb.components}
    assert kinds["evil"] == "altra fonte" and kinds["fromgit"] == "git"
    assert kinds["editable"] == "git" and kinds["localpkg"] == "locale"


def test_cyclonedx_license_id_only_for_spdx(test_repo, tmp_path):
    _, doc = _generate(test_repo, tmp_path)
    lic = {c["name"]: c.get("licenses") for c in doc["components"]}
    assert lic["lodash"] == [{"license": {"id": "MIT"}}]
    assert lic["fromgit"] == [{"license": {"name": "Proprietary"}}]    # non e' un identificativo SPDX
    assert lic["evil"] == [{"license": {"name": "UNLICENSED"}}]


def test_pyproject_optional_and_poetry_groups(tmp_path):
    pytest.importorskip("tomllib")                      # Python 3.11+
    root = write_tree(tmp_path / "py", {"pyproject.toml": (
        '[project]\nname="x"\ndependencies=["httpx>=0.27"]\n'
        '[project.optional-dependencies]\ntest=["pytest"]\nfast=["orjson"]\n'
        '[tool.poetry.group.docs.dependencies]\nmkdocs="*"\n')})
    deps, notes = builtin_sbom.collect(root)
    got = {d["name"]: d["dev"] for d in deps}
    assert got == {"httpx": False, "pytest": True, "orjson": False, "mkdocs": True}


def test_uv_lock_and_requirements_folder(tmp_path):
    root = write_tree(tmp_path / "uv", {
        "pyproject.toml": '[project]\nname="x"\ndependencies=[]\n',
        "uv.lock": ('version = 1\n\n[[package]]\nname = "x"\nversion = "0.1"\nsource = { editable = "." }\n\n'
                    '[[package]]\nname = "idna"\nversion = "3.10"\nsource = { registry = "https://pypi.org/simple" }\n'
                    'sdist = { url = "https://files.pythonhosted.org/i.tar.gz", hash = "sha256:' + "a" * 64 + '" }\n\n'
                    '[package.optional-dependencies]\nfast = [{ name = "z" }]\n\n'
                    '[[package]]\nname = "forked"\nversion = "1.0"\n'
                    'source = { git = "https://example.org/forked.git?rev=main#abc" }\n'),
        "requirements/dev.txt": "pytest==8.3.0\n"})
    deps, _ = builtin_sbom.collect(root)
    got = {d["name"]: (d["version"], d["source_kind"], bool(d["integrity"])) for d in deps}
    assert got["idna"] == ("3.10", "registry", True)
    assert got["forked"] == ("1.0", "git", False)
    assert got["pytest"][0] == "8.3.0" and "x" not in got


def test_cc_project_submodules_and_vendored(tmp_path):
    root = write_tree(tmp_path / "cc", {
        ".gitmodules": '[submodule "libuv"]\n\tpath = deps/libuv\n\turl = https://github.com/libuv/libuv.git\n',
        "src/main.c": "int main(){}", "third_party/cjson-1.7.15/cJSON.c": "",
        "CMakeLists.txt": ""})
    deps, notes = builtin_sbom.collect(root)
    got = {(d["name"], d["version"], d["source_kind"]) for d in deps}
    assert ("deps/libuv", None, "git") in got
    assert ("cjson", "1.7.15", "copiato") in got
    assert notes["vendored"] == 2


def test_js_library_copied_by_hand(tmp_path):
    # caso reale (zimlet Zimbra): CryptoJS copiato in lib/ con lo spazio nel nome, file -min.js
    lib = "z/lib/CryptoJS v3.1.2/"
    root = write_tree(tmp_path / "js", {
        "README.md": "x", "z/app.js": "/* codice del progetto 1.0 */",
        "z/lib/helpers.js": "",                                    # lib/ del progetto: non e' codice di terzi
        lib + "rollups/tripledes.js": "/*\nCryptoJS v3.1.2\ncode.google.com/p/crypto-js\n*/\nvar CryptoJS;",
        lib + "components/aes-min.js": "", lib + "components/md5-min.js": "", lib + "components/sha1-min.js": "",
        "static/jquery.min.js": "/*! jQuery v3.6.0 | (c) OpenJS Foundation */"})
    deps, notes = builtin_sbom.collect(root)
    got = {(d["name"], d["version"], d["eco"], d["source_kind"]) for d in deps}
    assert got == {("crypto-js", "3.1.2", "npm", "copiato"), ("jquery", "3.6.0", "npm", "copiato")}
    assert notes["vendored"] == 2
