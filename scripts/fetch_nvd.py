"""Download NVD CVE data to `data/knowledge_base/raw/nvd/`.

Targets a curated list of home-networking and IoT vendors. Each CVE is
written as `<CVE_ID>.json` (in our project's CVE schema, not NVD's raw
payload). Re-runs are idempotent: CVE IDs already on disk are skipped.

Kept separate from `build_kb.py` so the (slow) fetch can be re-run on its
own when we want to refresh the KB.

Usage:
    .venv/bin/python scripts/fetch_nvd.py
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Make the project root importable when running this file directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings  # noqa: E402
from rag.ingest.nvd_loader import fetch_nvd_cves  # noqa: E402

# CPE 2.3 vendor identifiers for the device classes a typical home network
# hosts: SOHO routers, IP cameras, NAS appliances, smart-home hubs.
TARGET_VENDORS = (
    "tp-link",
    "netgear",
    "d-link",
    "asus",
    "linksys",
    "ubiquiti",
    "tenda",
    "zyxel",
    "hikvision",
    "dahua",
    "synology",
    "qnap",
)

# CPE "part" axis: `h` = hardware, `o` = OS / firmware.
TARGET_PARTS = ("h", "o")


def main() -> None:
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
    )
    log = logging.getLogger("fetch_nvd")

    output_dir = settings.knowledge_base_path / "raw" / "nvd"
    output_dir.mkdir(parents=True, exist_ok=True)

    seen_ids = {p.stem for p in output_dir.glob("CVE-*.json")}
    log.info("Existing CVE files on disk: %d", len(seen_ids))

    new_count = 0
    for vendor in TARGET_VENDORS:
        for part in TARGET_PARTS:
            cpe_prefix = f"cpe:2.3:{part}:{vendor}"
            log.info("Fetching %s ...", cpe_prefix)

            for cve in fetch_nvd_cves(cpe_prefix=cpe_prefix):
                if cve.cve_id in seen_ids:
                    continue
                (output_dir / f"{cve.cve_id}.json").write_text(
                    cve.model_dump_json(indent=2)
                )
                seen_ids.add(cve.cve_id)
                new_count += 1
                if new_count % 50 == 0:
                    log.info("  cached %d new CVEs so far", new_count)

    log.info("Done. New: %d   Total on disk: %d", new_count, len(seen_ids))


if __name__ == "__main__":
    main()
