from sovrasbom.analyzers.licenses import best_license, classify_component, classify_expression, compatibility, is_osi
from sovrasbom.model import Component


def test_unlicensed_is_not_permissive():
    # in npm UNLICENSED significa "nessun permesso": il contrario di Unlicense
    assert classify_expression("UNLICENSED") == "Proprietaria / source-available"
    assert classify_expression("Unlicense") == "Permissiva"


def test_with_exception_keeps_the_license():
    assert classify_expression("GPL-2.0 WITH Classpath-exception-2.0") == "Copyleft forte"
    assert classify_expression("Apache-2.0 WITH LLVM-exception") == "Permissiva"
    assert classify_expression("(GPL-2.0-only WITH Classpath-exception-2.0 OR MIT)") == "Permissiva"


def test_or_takes_most_open_and_takes_most_restrictive():
    assert classify_expression("MIT OR GPL-3.0") == "Permissiva"
    assert classify_expression("MIT AND GPL-3.0") == "Copyleft forte"
    assert best_license("Apache-2.0 or AGPL-3.0") == ("Apache-2.0", "Permissiva")
    assert classify_component([]) == "Assente"


def test_osi():
    assert is_osi("Apache-2.0") and is_osi("EUPL-1.2") and not is_osi("BUSL-1.1")


def test_compatibility_table():
    comps = [Component("a", "1", licenses=["Apache-2.0"], ecosystem="java"),
             Component("b", "1", licenses=["AGPL-3.0-only"], ecosystem="npm"),
             Component("c", "1", licenses=["GPL-3.0"], ecosystem="deb"),           # pacchetto di sistema: escluso
             Component("d", "1", licenses=["UNLICENSED"], ecosystem="npm")]
    issues = compatibility(comps, "GPL-2.0-only")
    sev = {(i["severity"], c) for i in issues for c in i["components"]}
    assert ("Alta", "a (Apache-2.0)") in sev
    assert ("Alta", "b (AGPL-3.0-only)") in sev           # GPL-3/AGPL-3 incompatibili con GPL-2.0-only
    assert ("Alta", "d (UNLICENSED)") in sev
    assert not any("c (" in c for _, c in sev)
    mit = compatibility(comps, "MIT")
    assert any(i["severity"] == "Media" and "AGPL" in i["message"] for i in mit)
