import re

from .dkim import parse_tags
from .models import RecordResult, Status
from .resolver import NoRecord, Resolver, TemporaryDnsError

_DMARC_RE = re.compile(r"v=DMARC1\s*(;|$)", re.I)
POLICIES = {"none", "quarantine", "reject"}


async def check_dmarc(domain: str, resolver: Resolver) -> RecordResult:
    host = f"_dmarc.{domain}"
    try:
        txts = await resolver.txt(host)
    except NoRecord:
        txts = []
    except TemporaryDnsError:
        return RecordResult(Status.UNKNOWN, hint="DNS lookup failed temporarily; will retry.")

    records = [t.strip() for t in txts if _DMARC_RE.match(t.strip())]
    if not records:
        return RecordResult(
            Status.MISSING,
            hint=f"No DMARC record. Start with: v=DMARC1; p=none; rua=mailto:dmarc@{domain}",
        )
    if len(records) > 1:
        return RecordResult(Status.CONFLICT, found=" | ".join(records), hint="Publish exactly one DMARC record.")

    policy = parse_tags(records[0]).get("p", "").lower()
    if policy not in POLICIES:
        return RecordResult(Status.MISMATCH, found=records[0], hint="p= must be none, quarantine or reject.")
    hint = "p=none only monitors. Tighten to quarantine once reports look clean." if policy == "none" else None
    return RecordResult(Status.VALID, found=records[0], hint=hint)
