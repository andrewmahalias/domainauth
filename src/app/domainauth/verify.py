import asyncio

from .dkim import check_dkim
from .dmarc import check_dmarc
from .models import DomainReport
from .resolver import Resolver
from .spf import check_spf


async def verify_domain(
    domain: str,
    resolver: Resolver,
    *,
    spf_include: str,
    dkim_selector: str,
    dkim_expected: str,
) -> DomainReport:
    spf, dkim, dmarc = await asyncio.gather(
        check_spf(domain, resolver, spf_include),
        check_dkim(domain, dkim_selector, dkim_expected, resolver),
        check_dmarc(domain, resolver),
    )
    return DomainReport(domain, spf, dkim, dmarc)
