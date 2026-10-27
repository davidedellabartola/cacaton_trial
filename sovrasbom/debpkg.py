"""Apertura dei pacchetti .deb contenuti in un rilascio (es. l'archivio zcs-*.tgz di Zimbra).

Perche': un .deb e' a sua volta un archivio. Senza aprirlo, gli strumenti vedono solo
il NOME e la VERSIONE del pacchetto (es. zimbra-openssl 3.0.x); aprendolo vedono i
file veri: le librerie Java (.jar), i binari, OpenSSL incorporato. E' la differenza
tra leggere l'etichetta di una scatola e guardarci dentro.

Formato .deb: archivio "ar" che contiene control.tar.* (metadati) e data.tar.* (i file).
Estraiamo solo data.tar.*, con lo stesso filtro di sicurezza usato per gli archivi.
Compressioni supportate: gz, xz, bz2 (libreria standard) e zstd (Python 3.14+ oppure
il modulo 'zstandard'; Ubuntu comprime i propri pacchetti con zstd).
"""

import bz2
import gzip
import io
import lzma
import os
import tarfile

MAX_TOTAL = 4 * 1024 ** 3     # oltre 4 GB di pacchetti non apriamo nulla: troppo spazio su disco


def _skip_unsafe(member, path):
    """Filtro 'data' di Python, ma un elemento pericoloso viene SALTATO invece di bloccare tutto.

    I pacchetti contengono spesso collegamenti assoluti (es. -> /usr/lib/...): per l'analisi
    non servono, e fermarsi al primo farebbe perdere il resto del pacchetto.
    """
    try:
        return tarfile.data_filter(member, path)
    except tarfile.FilterError:
        return None


def _ar_members(fh):
    if fh.read(8) != b"!<arch>\n":
        raise ValueError("non e' un archivio ar")
    while True:
        header = fh.read(60)
        if len(header) < 60:
            return
        name = header[:16].decode("ascii", "ignore").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip() or 0)
        data_start = fh.tell()
        yield name, data_start, size
        fh.seek(data_start + size + (size % 2))


def _zstd_reader(raw):
    try:
        from compression import zstd           # Python 3.14+
        return zstd.ZstdFile(raw)
    except ImportError:
        pass
    try:
        import zstandard                       # pip install zstandard
        return zstandard.ZstdDecompressor().stream_reader(raw)
    except ImportError:
        return None


def _data_stream(path, member="data.tar"):
    """Restituisce (stream decompresso di data.tar, nome compressione) oppure (None, motivo)."""
    fh = open(path, "rb")
    for name, start, size in _ar_members(fh):
        if not name.startswith(member):
            continue
        fh.seek(start)
        raw = io.BytesIO(fh.read(size))
        fh.close()
        if name.endswith(".gz"):
            return gzip.GzipFile(fileobj=raw), "gz"
        if name.endswith(".xz"):
            return lzma.LZMAFile(raw), "xz"
        if name.endswith(".bz2"):
            return bz2.BZ2File(raw), "bz2"
        if name.endswith(".zst"):
            reader = _zstd_reader(raw)
            return (reader, "zst") if reader else (None, "zstd non disponibile (pip install zstandard)")
        if name == member:
            return raw, "nessuna"
        return None, f"compressione sconosciuta ({name})"
    fh.close()
    return None, f"{member} non trovato"


def read_control(path: str) -> dict:
    """Legge i metadati del pacchetto (Package, Version, Maintainer...) dal file control."""
    try:
        stream, _ = _data_stream(path, "control.tar")
        if stream is None:
            return {}
        with tarfile.open(fileobj=stream, mode="r|") as tf:
            for m in tf:
                if m.isfile() and m.name.lstrip("./") == "control":
                    text = tf.extractfile(m).read().decode("utf-8", "ignore")
                    fields, key = {}, None
                    for line in text.splitlines():
                        if line[:1] in (" ", "\t") and key:
                            continue                      # righe di continuazione (descrizione lunga)
                        if ":" in line:
                            key, val = line.split(":", 1)
                            fields[key.strip()] = val.strip()
                    return fields
    except (OSError, ValueError, tarfile.TarError, EOFError):
        pass
    return {}


def expand_debs(root: str, log=print) -> dict:
    """Apre ogni .deb sotto `root` in una cartella accanto ('<pacchetto>.contenuto')."""
    debs = []
    for dp, _, fn in os.walk(root):
        debs += [os.path.join(dp, f) for f in fn if f.endswith(".deb")]
    result = {"debs": len(debs), "expanded": 0, "skipped": []}
    if not debs:
        return result
    total = sum(os.path.getsize(d) for d in debs)
    if total > MAX_TOTAL:
        result["skipped"].append(f"{len(debs)} pacchetti ({total // 1024 ** 2} MB): troppo grandi, non aperti")
        return result
    log(f"Apro {len(debs)} pacchetti .deb per vedere i file che contengono...")
    for deb in sorted(debs):
        dest = deb + ".contenuto"
        try:
            stream, how = _data_stream(deb)
            if stream is None:
                result["skipped"].append(f"{os.path.basename(deb)}: {how}")
                continue
            with tarfile.open(fileobj=stream, mode="r|") as tf:
                try:
                    tf.extractall(dest, filter=_skip_unsafe)
                except TypeError:                     # Python senza filtri: estrazione prudente
                    real = os.path.realpath(dest)
                    for m in tf:
                        target = os.path.realpath(os.path.join(dest, m.name))
                        if (m.isfile() or m.isdir()) and target.startswith(real + os.sep):
                            tf.extract(m, dest)
            result["expanded"] += 1
        except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
            result["skipped"].append(f"{os.path.basename(deb)}: {str(exc)[:80]}")
    return result
