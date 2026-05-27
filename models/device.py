"""Device and port schemas — output of Nmap-based scans."""

from typing import Literal

from pydantic import BaseModel, Field


class Port(BaseModel):
    """A single open port on a device."""

    number: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    state: Literal["open", "closed", "filtered"] = "open"
    service: str | None = None
    product: str | None = None
    version: str | None = None


class Device(BaseModel):
    """A discovered host on the LAN."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    device_type: str | None = None
    ports: list[Port] = Field(default_factory=list)
    is_gateway: bool = False
