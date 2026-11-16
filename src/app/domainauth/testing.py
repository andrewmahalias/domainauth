from .resolver import NoRecord


class FakeResolver:
    """In-memory zone for tests. Value is a list of TXT strings, or an Exception to raise."""

    def __init__(self, zone: dict[str, list[str] | Exception] | None = None):
        self.zone = {k.lower().rstrip("."): v for k, v in (zone or {}).items()}

    async def txt(self, name: str) -> list[str]:
        value = self.zone.get(name.lower().rstrip("."))
        if value is None:
            raise NoRecord(name)
        if isinstance(value, Exception):
            raise value
        return list(value)
