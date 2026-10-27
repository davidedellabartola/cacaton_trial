import json

from sovrasbom.sbom import detect_format, inspect_text, parse_text

SPDX_JSON = {
    "spdxVersion": "SPDX-2.3", "name": "myapp", "documentDescribes": ["SPDXRef-root"],
    "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: syft-1.0"]},
    "packages": [
        {"SPDXID": "SPDXRef-root", "name": "myapp", "versionInfo": "1.0"},
        {"SPDXID": "SPDXRef-lodash", "name": "lodash", "versionInfo": "4.17.21", "licenseConcluded": "MIT",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}]},
    ],
    "relationships": [{"spdxElementId": "SPDXRef-root", "relationshipType": "DEPENDS_ON",
                       "relatedSpdxElement": "SPDXRef-lodash"}],
}

SPDX_TV = """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
DocumentName: myapp
Creator: Tool: example-1.0
Created: 2026-01-01T00:00:00Z
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-root

PackageName: myapp
SPDXID: SPDXRef-root
PackageVersion: 1.0

PackageName: lodash
SPDXID: SPDXRef-lodash
PackageVersion: 4.17.21
PackageLicenseConcluded: MIT
PackageComment: <text>riga uno
riga due</text>
ExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.21
"""

CDX_XML = """<?xml version="1.0"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata><timestamp>2026-01-01T00:00:00Z</timestamp>
    <tools><tool><name>maven-plugin</name><version>2.7</version></tool></tools>
    <component type="application" bom-ref="root"><name>myapp</name></component></metadata>
  <components>
    <component type="library" bom-ref="pkg:maven/org.slf4j/slf4j-api@2.0.9">
      <group>org.slf4j</group><name>slf4j-api</name><version>2.0.9</version>
      <licenses><license><id>MIT</id></license></licenses>
      <purl>pkg:maven/org.slf4j/slf4j-api@2.0.9</purl>
      <hashes><hash alg="SHA-256">abcd</hash></hashes>
    </component>
  </components>
  <dependencies><dependency ref="root"><dependency ref="pkg:maven/org.slf4j/slf4j-api@2.0.9"/></dependency></dependencies>
</bom>
"""


def test_spdx_root_package_is_not_a_component():
    sb = parse_text(json.dumps(SPDX_JSON))
    assert [c.name for c in sb.components] == ["lodash"]
    assert sb.subject == "myapp"
    assert sb.components[0].direct is True


def test_spdx_tag_value():
    assert detect_format(SPDX_TV) == "spdx-tv"
    sb = parse_text(SPDX_TV)
    assert sb.fmt.startswith("SPDX tag-value")
    assert [(c.name, c.version, c.purl, c.licenses) for c in sb.components] == \
        [("lodash", "4.17.21", "pkg:npm/lodash@4.17.21", ["MIT"])]


def test_cyclonedx_xml():
    assert detect_format(CDX_XML) == "cdx-xml"
    sb = parse_text(CDX_XML)
    c = sb.components[0]
    assert (c.name, c.version, c.licenses, c.namespace, c.direct) == ("slf4j-api", "2.0.9", ["MIT"], "org.slf4j", True)
    assert sb.author_tools == ["maven-plugin 2.7"] and sb.has_dependencies


def test_inspect_published_sboms():
    ok = inspect_text(CDX_XML, "bom.xml")
    assert ok["valid"] and ok["completeness"] == 1.0
    assert inspect_text('{"bomFormat": "CycloneDX", "components": []}', "sbom.json")["valid"] is False
    assert inspect_text('{"hello": 1}', "sbom.json")["valid"] is False
    assert inspect_text(SPDX_TV, "x.spdx")["components"] == 1
