from typing import Protocol


class NoRecord(Exception):
    """Definitive answer: NXDOMAIN or no TXT data."""


class TemporaryDnsError(Exception):
    """Timeout, SERVFAIL or similar. The answer is unknown, not 'missing'."""


class Resolver(Protocol):
    async def txt(self, name: str) -> list[str]:
        """Return TXT records, each with its character-strings already joined."""


class DnsPythonResolver:
    """Production resolver. Uses public resolvers, not the host's resolv.conf."""

    def __init__(self, nameservers: tuple[str, ...] = ("1.1.1.1", "8.8.8.8"), timeout: float = 3.0):
        import dns.asyncresolver

        self._r = dns.asyncresolver.Resolver(configure=False)
        self._r.nameservers = list(nameservers)
        self._r.timeout = timeout
        self._r.lifetime = timeout * 2

    async def txt(self, name: str) -> list[str]:
        import dns.exception
        import dns.resolver

        try:
            answer = await self._r.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
            raise NoRecord(name) from exc
        except dns.exception.DNSException as exc:  # Timeout, NoNameservers (SERVFAIL), ...
            raise TemporaryDnsError(f"{name}: {exc.__class__.__name__}") from exc
        return ["".join(s.decode("utf-8", "replace") for s in rdata.strings) for rdata in answer]
