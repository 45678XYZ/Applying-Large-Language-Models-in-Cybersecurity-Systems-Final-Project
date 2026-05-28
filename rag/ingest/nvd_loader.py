"""Fetch CVE records from the NVD 2.0 API and normalise them.

Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Iterator

import requests

from models import CVE

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_PAGE_SIZE = 2000  # NVD's maximum

# NVD rate limits: 5 req / 30s anonymous, 50 req / 30s with API key.
# Conservative per-request sleeps (a tad above the documented minimum).
_DELAY_WITHOUT_KEY = 6.0
_DELAY_WITH_KEY = 0.7

_log = logging.getLogger(__name__)


def fetch_nvd_cves(
    keyword: str | None = None,
    cpe_prefix: str | None = None,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> Iterator[CVE]:
    """Yield CVEs from NVD filtered by either `keyword` or `cpe_prefix`.

    Pagination, transient-error retry, and rate-limit pacing are handled
    internally so callers can iterate the result as a plain generator.

    `cpe_prefix` is matched against CPE Match Criteria via NVD's
    `virtualMatchString` parameter — e.g. `"cpe:2.3:o:tp-link"` returns
    all CVEs whose configurations cite TP-Link firmware.
    """
    if not keyword and not cpe_prefix:
        raise ValueError("Must provide either keyword or cpe_prefix")

    api_key = os.getenv("NVD_API_KEY", "").strip()
    headers = {"apiKey": api_key} if api_key else {}
    delay = _DELAY_WITH_KEY if api_key else _DELAY_WITHOUT_KEY

    start_index = 0
    total_results: int | None = None

    while True:
        params: dict[str, Any] = {
            "startIndex": start_index,
            "resultsPerPage": page_size,
        }
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_prefix:
            params["virtualMatchString"] = cpe_prefix

        data = _request_with_retry(params, headers)

        if total_results is None:
            total_results = int(data.get("totalResults", 0))
            _log.info(
                "NVD query (%s) → %d total results",
                cpe_prefix or keyword,
                total_results,
            )

        for vuln in data.get("vulnerabilities", []):
            parsed = _parse_cve(vuln.get("cve", {}))
            if parsed is not None:
                yield parsed

        start_index += page_size
        if start_index >= total_results:
            return
        time.sleep(delay)


def _request_with_retry(
    params: dict[str, Any],
    headers: dict[str, str],
    max_attempts: int = 4,
) -> dict[str, Any]:
    """GET the NVD endpoint with exponential backoff on 429 / 5xx."""
    backoff = 2.0
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.get(
                NVD_API_BASE, params=params, headers=headers, timeout=60
            )
        except requests.RequestException as exc:
            if attempt == max_attempts:
                raise
            _log.warning("NVD request error (%s); retrying in %.1fs", exc, backoff)
            time.sleep(backoff)
            backoff *= 2
            continue

        if response.status_code in (429, 503) and attempt < max_attempts:
            _log.warning(
                "NVD %d on attempt %d; sleeping %.1fs",
                response.status_code,
                attempt,
                backoff,
            )
            time.sleep(backoff)
            backoff *= 2
            continue

        response.raise_for_status()
        return response.json()

    raise RuntimeError("NVD request exhausted retries")


def _parse_cve(cve_data: dict[str, Any]) -> CVE | None:
    """Convert NVD's JSON CVE structure into our `CVE` schema."""
    cve_id = cve_data.get("id")
    if not cve_id:
        return None

    description = _english_description(cve_data.get("descriptions", []))
    cvss_score, cvss_severity = _best_cvss(cve_data.get("metrics", {}))
    affected = _affected_cpes(cve_data.get("configurations", []))
    references = [
        ref["url"]
        for ref in cve_data.get("references", [])
        if isinstance(ref, dict) and ref.get("url")
    ]

    return CVE(
        cve_id=cve_id,
        cvss_score=cvss_score,
        cvss_severity=cvss_severity,
        description=description,
        affected_products=affected,
        published=cve_data.get("published"),
        references=references,
    )


def _english_description(descriptions: list[dict[str, Any]]) -> str:
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "") or ""
    return ""


def _best_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    """Pick the most authoritative CVSS score available (v3.1 > v3.0 > v2)."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData", {}) or {}
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
        return (float(score) if score is not None else None, severity)
    return (None, None)


def _affected_cpes(configurations: list[dict[str, Any]]) -> list[str]:
    cpes: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria") or ""
                if criteria and criteria not in cpes:
                    cpes.append(criteria)
    return cpes
