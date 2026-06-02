"""Load OWASP / NIST / CIS static documents from disk.

Walks `root` recursively, dispatches by extension, and yields
`(text, metadata)` for every supported file. Empty / unreadable files are
silently skipped. NVD CVE JSONs are excluded — those have their own loader.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from pathlib import Path

_log = logging.getLogger(__name__)


def load_static_documents(root: Path) -> Iterator[tuple[str, dict]]:
    """Yield `(text, metadata)` for every supported KB document under `root`.

    Metadata example: `{"source": "owasp", "path": "owasp/iot-top-10.md",
    "filename": "iot-top-10.md"}`. The first path segment under `root` is
    treated as the source label.
    """
    if not root.exists():
        _log.warning("KB root %s does not exist", root)
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file() or _should_skip(path):
            continue

        loader = _LOADERS.get(path.suffix.lower())
        if loader is None:
            continue

        try:
            text = loader(path)
        except Exception as exc:  # noqa: BLE001 — log and continue is the right policy here
            _log.warning("Failed to load %s: %s", path, exc)
            continue

        if not text or not text.strip():
            continue

        yield text, _metadata_for(path, root)


def _should_skip(path: Path) -> bool:
    if path.name.startswith("."):
        return True
    # CVE JSONs handled by nvd_loader.
    if path.parent.name == "nvd" and path.suffix == ".json":
        return True
    return False


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _load_pdf(path: Path) -> str:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    pages = [page.extract_text() or "" for page in reader.pages]
    return "\n\n".join(p for p in pages if p.strip())


def _load_html(path: Path) -> str:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    # Strip scripts/styles whole-block first, then collapse remaining tags.
    raw = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
    raw = re.sub(r"<[^>]+>", " ", raw)
    return re.sub(r"\s+", " ", raw).strip()


_LOADERS: dict[str, Callable[[Path], str]] = {
    ".md": _load_text,
    ".txt": _load_text,
    ".pdf": _load_pdf,
    ".html": _load_html,
    ".htm": _load_html,
}


def _metadata_for(path: Path, root: Path) -> dict:
    rel = path.relative_to(root)
    source = rel.parts[0] if len(rel.parts) > 1 else "kb"
    return {
        "source": source,
        "path": str(rel),
        "filename": path.name,
    }
