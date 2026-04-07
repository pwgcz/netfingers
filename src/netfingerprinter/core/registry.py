from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netfingerprinter.probers.base import BaseProber

_BY_NAME: dict[str, type["BaseProber"]] = {}
_BY_PORT: dict[int, type["BaseProber"]] = {}


def register(name: str, ports: list[int]):
    """Class decorator that registers a prober by name and default ports."""

    def decorator(cls: type["BaseProber"]) -> type["BaseProber"]:
        _BY_NAME[name] = cls
        for port in ports:
            _BY_PORT[port] = cls
        return cls

    return decorator


def get_prober_by_name(name: str) -> type["BaseProber"] | None:
    return _BY_NAME.get(name)


def get_prober_for_port(port: int) -> type["BaseProber"] | None:
    return _BY_PORT.get(port)


def all_probers() -> list[type["BaseProber"]]:
    return list(_BY_NAME.values())
