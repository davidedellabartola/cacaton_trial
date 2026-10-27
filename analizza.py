#!/usr/bin/env python3
"""Lanciatore di SovraSBOM: un argomento (o piu'), qualunque cosa sia.

    python3 analizza.py https://github.com/owner/repo/tree/v1.2.3
    python3 analizza.py owner/repo
    python3 analizza.py ./cartella-o-archivio.zip
    python3 analizza.py sbom.cdx.json
    python3 analizza.py a.zip b.zip --md confronto.md    (piu' input: tabella di confronto)

Funziona da qualunque cartella: python3 ~/sovrasbom/analizza.py <input>
"""

import os
import sys

# rende importabile il pacchetto anche se il comando viene lanciato da un'altra cartella
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sovrasbom.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
