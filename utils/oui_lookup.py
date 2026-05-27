"""MAC address → vendor name lookup (IEEE OUI database)."""


def lookup_vendor(mac: str) -> str | None:
    """Resolve the first 3 octets of `mac` to an organisation name."""
    raise NotImplementedError
