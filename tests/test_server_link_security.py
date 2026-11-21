"""3011 互联口 fail-closed 回归测试。"""
from __future__ import annotations

import asyncio

from fsd.server_link import ServerLink


class _Writer:
    def __init__(self) -> None:
        self.closed = False

    def get_extra_info(self, _name, default=None):
        return ("198.51.100.10", 12345)

    def close(self) -> None:
        self.closed = True


class _Config:
    def getlist(self, _section, _key):
        return []


class _Server:
    config = _Config()


def test_empty_allowfrom_denies_server_link() -> None:
    writer = _Writer()
    link = ServerLink(_Server(), None, writer)
    asyncio.run(link.run())
    assert writer.closed is True
