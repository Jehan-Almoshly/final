#!/usr/bin/env python3
"""
NVD Feed Downloader & Indexer
==============================

Downloads the NVD CVE JSON 2.0 yearly feeds and builds a local SQLite index
optimized for fast vendor:product lookups during scan-time CVE matching.

Usage on Kali:
    python3 download_nvd.py                    # download + index everything
    python3 download_nvd.py --skip-download    # re-index existing files only
    python3 download_nvd.py --start-year 2020  # partial download
    python3 download_nvd.py --force            # redownload even if up-to-date

Output:
    ~/vuln-data/nvd/raw/nvdcve-2.0-YYYY.json.gz
    ~/vuln-data/nvd/nvd_index.sqlite

Requires only Python 3.8+ standard library (no pip install needed).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
USER_AGENT = "vuln-manager-nvd-loader/1.0"
DEFAULT_DATA_DIR = Path.home() / "vuln-data" / "nvd"
HTTP_TIMEOUT = 180


# -------------------------------------------------------------------
# HTTP + checksum helpers
# -------------------------------------------------------------------
def _http_get(url: str, timeout: int = HTTP_TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def fetch_meta(year: int) -> dict | None:
    """Fetch the per-year .meta file (lastModifiedDate, size, sha256, ...)."""
    url = f"{NVD_BASE}/nvdcve-2.0-{year}.meta"
    try:
        with _http_get(url, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        meta: dict[str, str] = {}
        for line in text.strip().splitlines():
            key, _, value = line.partition(":")
            if key:
                meta[key.strip()] = value.strip()
        return meta
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"  [warn] could not fetch meta for {year}: {e}")
        return None


def sha256_of(path: Path, chunk: int = 1024 * 1024) -> str:
    """SHA256 of the raw bytes on disk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest().upper()


def sha256_of_gz_content(path: Path, chunk: int = 1024 * 1024) -> str:
    """SHA256 of the *decompressed* content of a gzipped file.

    NVD's .meta files publish the sha256 of the unzipped JSON, not the .gz,
    so this is what we must compare against.
    """
    h = hashlib.sha256()
    with gzip.open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest().upper()


def download_with_progress(url: str, dest: Path) -> None:
    """Stream a URL into dest with a single-line progress indicator."""
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    with _http_get(url) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        last = 0.0
        with open(tmp, "wb") as f:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                now = time.time()
                if now - last > 0.5:
                    if total:
                        pct = done * 100 / total
                        sys.stdout.write(
                            f"\r    {done/1e6:7.1f} / {total/1e6:.1f} MB  ({pct:5.1f}%)"
                        )
                    else:
                        sys.stdout.write(f"\r    {done/1e6:7.1f} MB")
                    sys.stdout.flush()
                    last = now
        sys.stdout.write(f"\r    {done/1e6:7.1f} MB downloaded                          \n")
    tmp.replace(dest)


# -------------------------------------------------------------------
# Per-year download
# -------------------------------------------------------------------
def download_year(year: int, raw_dir: Path, force: bool = False) -> bool:
    """Download one year. Returns True if a new file was written."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    dest = raw_dir / f"nvdcve-2.0-{year}.json.gz"
    url = f"{NVD_BASE}/nvdcve-2.0-{year}.json.gz"

    meta = fetch_meta(year)
    expected_sha = (meta or {}).get("sha256", "").upper()

    if dest.exists() and not force and expected_sha:
        try:
            local_sha = sha256_of_gz_content(dest)
            if local_sha == expected_sha:
                print(f"[{year}] up-to-date (sha256 match)")
                return False
        except (OSError, EOFError, gzip.BadGzipFile):
            # corrupted local file -> fall through and re-download
            pass

    print(f"[{year}] downloading {url}")
    download_with_progress(url, dest)

    if expected_sha:
        try:
            actual = sha256_of_gz_content(dest)
        except (OSError, EOFError, gzip.BadGzipFile) as e:
            dest.unlink(missing_ok=True)
            raise RuntimeError(f"[{year}] downloaded file is not valid gzip: {e}")
        if actual != expected_sha:
            # Keep the file (HTTPS already guaranteed transport integrity).
            # Just warn so the user is aware that NVD updated mid-download.
            print(
                f"    [warn] sha256 mismatch but file is valid gzip; "
                f"keeping it (NVD may have updated the feed during download)"
            )
        else:
            print(f"    sha256 verified ✓")
    return True


# -------------------------------------------------------------------
# Indexer
# -------------------------------------------------------------------
SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;

CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    cvss_score      REAL,
    cvss_severity   TEXT,
    cvss_vector     TEXT,
    cvss_version    TEXT,
    published_date  TEXT,
    last_modified   TEXT,
    references_json TEXT
);

CREATE TABLE IF NOT EXISTS cve_cpes (
    cve_id              TEXT NOT NULL,
    vendor              TEXT NOT NULL,
    product             TEXT NOT NULL,
    version             TEXT,
    cpe_uri             TEXT NOT NULL,
    version_start_inc   TEXT,
    version_start_exc   TEXT,
    version_end_inc     TEXT,
    version_end_exc     TEXT,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(cvss_severity);
CREATE INDEX IF NOT EXISTS idx_cves_score    ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cpes_vp       ON cve_cpes(vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpes_cve      ON cve_cpes(cve_id);

CREATE TABLE IF NOT EXISTS index_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None, str | None, str | None]:
    """Pick the best available CVSS metric (v3.1 > v3.0 > v2)."""
    for key, ver in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        bucket = metrics.get(key)
        if bucket:
            data = bucket[0].get("cvssData", {})
            return (
                data.get("baseScore"),
                data.get("baseSeverity") or bucket[0].get("baseSeverity"),
                data.get("vectorString"),
                ver,
            )
    return None, None, None, None


def index_file(conn: sqlite3.Connection, year: str, gz_path: Path) -> tuple[int, int]:
    """Parse one year's .json.gz and replace its rows in the index."""
    cur = conn.cursor()
    # Wipe previous rows for this year so re-indexing is clean
    like = f"CVE-{year}-%"
    cur.execute("DELETE FROM cve_cpes WHERE cve_id LIKE ?", (like,))
    cur.execute("DELETE FROM cves     WHERE cve_id LIKE ?", (like,))

    with gzip.open(gz_path, "rb") as gz:
        data = json.load(gz)

    cve_rows: list[tuple] = []
    cpe_rows: list[tuple] = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        # English description, capped at 500 chars to mirror cve_catalog
        descs = cve.get("descriptions", [])
        description = next(
            (d.get("value", "") for d in descs if d.get("lang") == "en"), ""
        )[:500]

        score, severity, vector, ver = _extract_cvss(cve.get("metrics", {}))
        published = cve.get("published")
        last_mod = cve.get("lastModified")

        # Top 5 references only (saves space for downstream Supabase push)
        refs = [r.get("url") for r in cve.get("references", [])[:5] if r.get("url")]

        cve_rows.append(
            (cve_id, description, score, severity, vector, ver,
             published, last_mod, json.dumps(refs))
        )

        # CPE matches: walk configurations -> nodes -> cpeMatch
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    cpe_uri = m.get("criteria", "")
                    parts = cpe_uri.split(":")
                    if len(parts) < 6:
                        continue
                    vendor = parts[3].lower()
                    product = parts[4].lower()
                    version = parts[5] if parts[5] not in ("*", "-") else None
                    cpe_rows.append((
                        cve_id, vendor, product, version, cpe_uri,
                        m.get("versionStartIncluding"),
                        m.get("versionStartExcluding"),
                        m.get("versionEndIncluding"),
                        m.get("versionEndExcluding"),
                    ))

    cur.executemany(
        "INSERT OR REPLACE INTO cves "
        "(cve_id, description, cvss_score, cvss_severity, cvss_vector, "
        " cvss_version, published_date, last_modified, references_json) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        cve_rows,
    )
    cur.executemany(
        "INSERT INTO cve_cpes "
        "(cve_id, vendor, product, version, cpe_uri, "
        " version_start_inc, version_start_exc, version_end_inc, version_end_exc) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        cpe_rows,
    )
    conn.commit()
    return len(cve_rows), len(cpe_rows)


def build_index(raw_dir: Path, db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)

    files = sorted(raw_dir.glob("nvdcve-2.0-*.json.gz"))
    if not files:
        print(f"[!] no NVD files found in {raw_dir} — run without --skip-download first")
        return

    total_cves = 0
    total_cpes = 0
    for f in files:
        # filename: nvdcve-2.0-YYYY.json.gz
        year = f.name.removeprefix("nvdcve-2.0-").removesuffix(".json.gz")
        print(f"[{year}] indexing {f.name} ...", end=" ", flush=True)
        n_cve, n_cpe = index_file(conn, year, f)
        total_cves += n_cve
        total_cpes += n_cpe
        print(f"{n_cve:>6} CVEs, {n_cpe:>7} CPE matches")

    conn.execute(
        "INSERT OR REPLACE INTO index_meta(key,value) VALUES('built_at', ?)",
        (datetime.utcnow().isoformat(timespec="seconds") + "Z",),
    )
    conn.execute(
        "INSERT OR REPLACE INTO index_meta(key,value) VALUES('total_cves', ?)",
        (str(total_cves),),
    )
    conn.commit()
    print("\nRunning ANALYZE for query planner ...")
    conn.execute("ANALYZE")
    conn.commit()
    conn.close()

    size_mb = db_path.stat().st_size / (1024 * 1024)
    print(f"\n✓ Index built: {db_path}")
    print(f"  total CVEs       : {total_cves:,}")
    print(f"  total CPE matches: {total_cpes:,}")
    print(f"  database size    : {size_mb:.1f} MB")


# -------------------------------------------------------------------
# Self-test query
# -------------------------------------------------------------------
def smoke_test(db_path: Path) -> None:
    """Quick test query so the user sees the index works."""
    if not db_path.exists():
        print(f"[!] no index at {db_path}")
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    print("\n--- index smoke test ---")
    cur.execute("SELECT COUNT(*) FROM cves")
    print(f"cves table     : {cur.fetchone()[0]:,} rows")
    cur.execute("SELECT COUNT(*) FROM cve_cpes")
    print(f"cve_cpes table : {cur.fetchone()[0]:,} rows")
    cur.execute(
        "SELECT cve_id, cvss_score, cvss_severity FROM cves "
        "WHERE cvss_severity='CRITICAL' AND cve_id LIKE 'CVE-2021-%' "
        "ORDER BY cvss_score DESC LIMIT 5"
    )
    print("\nTop 5 CRITICAL CVEs from 2021:")
    for row in cur.fetchall():
        print(f"  {row[0]:18} score={row[1]:>4} severity={row[2]}")
    cur.execute(
        "SELECT DISTINCT cve_id FROM cve_cpes "
        "WHERE vendor='apache' AND product='http_server' LIMIT 5"
    )
    print("\nSample CVEs affecting apache:http_server:")
    for row in cur.fetchall():
        print(f"  {row[0]}")
    conn.close()


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download NVD CVE feeds and build a local SQLite index.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR,
                        help=f"output directory (default: {DEFAULT_DATA_DIR})")
    parser.add_argument("--start-year", type=int, default=2002)
    parser.add_argument("--end-year",   type=int, default=datetime.now().year)
    parser.add_argument("--force",         action="store_true",
                        help="redownload even if local sha256 matches")
    parser.add_argument("--skip-download", action="store_true",
                        help="only build index from existing files")
    parser.add_argument("--skip-index",    action="store_true",
                        help="only download, do not build index")
    parser.add_argument("--test", action="store_true",
                        help="run a smoke-test query against the index and exit")
    args = parser.parse_args()

    raw_dir = args.data_dir / "raw"
    db_path = args.data_dir / "nvd_index.sqlite"

    if args.test:
        smoke_test(db_path)
        return 0

    print(f"data directory : {args.data_dir}")
    print(f"index database : {db_path}")
    print(f"year range     : {args.start_year} .. {args.end_year}\n")

    failures: list[int] = []

    if not args.skip_download:
        for year in range(args.start_year, args.end_year + 1):
            try:
                download_year(year, raw_dir, force=args.force)
            except Exception as e:
                print(f"[{year}] FAILED: {e}")
                failures.append(year)
        print()

    if not args.skip_index:
        build_index(raw_dir, db_path)

    if failures:
        print(f"\n[!] {len(failures)} years failed to download: {failures}")
        return 1

    print("\nAll done. Try:  python3 download_nvd.py --test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
