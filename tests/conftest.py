"""Repository di esempio costruiti al volo: piccoli, leggibili, senza rete."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def write_tree(root, files: dict):
    for rel, content in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not isinstance(content, str):
            content = json.dumps(content, indent=1)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return str(root)


PACKAGE_LOCK = {
    "name": "myapp", "lockfileVersion": 3,
    "packages": {
        "": {"name": "myapp", "dependencies": {"lodash": "^4", "evil": "*", "fromgit": "*", "nolic": "*"}},
        "node_modules/lodash": {"version": "4.17.21", "license": "MIT",
                                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                                "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="},
        "node_modules/evil": {"version": "1.0.0", "license": "UNLICENSED",
                              "resolved": "https://evil.example.com/evil-1.0.0.tgz"},
        "node_modules/fromgit": {"version": "2.0.0", "license": "Proprietary",
                                 "resolved": "git+https://github.com/someone/fromgit.git#abc"},
        "node_modules/nolic": {"version": "0.1.0",
                               "resolved": "https://registry.npmjs.org/nolic/-/nolic-0.1.0.tgz"},
    },
}

TEST_REPO = {
    "LICENSE": "MIT License\n\nPermission is hereby granted, free of charge, to any person...",
    "README.md": "# myapp\n\nExport data in formati standard; backup e ripristino documentati.\n",
    "package.json": {"name": "myapp", "license": "MIT",
                     "dependencies": {"lodash": "^4", "evil": "*", "fromgit": "*", "nolic": "*"}},
    "package-lock.json": PACKAGE_LOCK,
    "requirements.txt": ("--extra-index-url https://pypi.internal.example/simple\n"
                         "requests==2.31.0\n-e git+https://github.com/org/editable.git#egg=editable\n"
                         "-e ./libs/localpkg\n"),
    "vcpkg.json": {"name": "native", "dependencies": ["zlib", {"name": "openssl"}],
                   "overrides": [{"name": "zlib", "version": "1.3.1"}]},
    "conanfile.txt": "[requires]\nfmt/10.2.1\n\n[tool_requires]\ncmake/3.27.0\n",
    "legacy/packages.config": '<?xml version="1.0"?><packages><package id="Newtonsoft.Json" version="13.0.3" /></packages>',
    "java/pom.xml": ("<project><modelVersion>4.0.0</modelVersion><version>1.0</version>"
                     "<properties><guava.version>33.0.0-jre</guava.version></properties>"
                     "<dependencyManagement><dependencies><dependency><groupId>org.slf4j</groupId>"
                     "<artifactId>slf4j-api</artifactId><version>2.0.9</version></dependency></dependencies>"
                     "</dependencyManagement><dependencies>"
                     "<dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>"
                     "<dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId>"
                     "<version>${guava.version}</version></dependency></dependencies></project>"),
    "android/build.gradle": "dependencies { implementation 'com.squareup.okhttp3:okhttp:4.12.0' }\n",
    "third_party/zlib-1.2.13/zlib.h": "/* copia */\n",
    ".github/workflows/ci.yml": (
        "on:\n  pull_request_target:\n  issues:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    container:\n      image: python:3.9-slim\n"
        "    steps:\n"
        "      # - uses: evil/commented@v1\n"
        "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - uses: third/party-action@v2\n"
        "      - run: |\n          echo \"${{ github.event.issue.title }}\"\n"
        "      - run: echo ok\n"),
}


@pytest.fixture
def test_repo(tmp_path):
    return write_tree(tmp_path / "myapp", TEST_REPO)
