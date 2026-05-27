"""Load OWASP IoT Top 10 / CIS / NIST static documents from disk."""

from pathlib import Path
from typing import Iterator


def load_static_documents(root: Path) -> Iterator[tuple[str, dict]]:
    """Yield `(text, metadata)` for every markdown/PDF/HTML doc under `root`.

    Metadata example: {"source": "owasp_iot_top10", "section": "I1"}.
    """
    raise NotImplementedError
