from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..client import AscClient


class BaseResource:
    def __init__(self, client: "AscClient") -> None:
        self._c = client
