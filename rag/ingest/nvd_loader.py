"""Fetch CVE records from the NVD 2.0 API and normalise them."""

from typing import Iterator

from models import CVE


def fetch_nvd_cves(
    keyword: str | None = None,
    cpe_prefix: str | None = None,
) -> Iterator[CVE]:
    """Stream CVEs from NVD, filtered by keyword or CPE prefix.

    Uses `NVD_API_KEY` if available to lift rate limits.
    """
    raise NotImplementedError
