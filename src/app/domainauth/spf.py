import re

from .models import RecordResult, Status
from .resolver import NoRecord, Resolver, TemporaryDnsError

MAX_LOOKUPS = 10
_SPF_RE = re.compile(r"v=spf1(\s|$)", re.I)


def find_spf(txt_records: list[str]) -> list[str]:
    return [r.strip() for r in txt_records if _SPF_RE.match(r.strip())]


def _terms(record: str) -> list[str]:
    return record.split()[1:]


def _split(term: str) -> tuple[str, str, str | None]:
    """'~all' -> ('~','all',None); 'include:x.com' -> ('+','include','x.com')."""
    qualifier = "+"
    if term and term[0] in "+-~?":
        qualifier, term = term[0], term[1:]
    m = re.match(r"([A-Za-z0-9]+)(?:[:=](.*))?", term)
    if not m:
        return qualifier, "", None
    return qualifier, m.group(1).lower(), m.group(2)


async def count_lookups(record: str, resolver: Resolver, seen: set[str] | None = None) -> int:
    """DNS-lookup terms per RFC 7208 section 4.6.4, following include/redirect."""
    if seen is None:
        seen = set()
    total = 0
    for term in _terms(record):
        _, name, value = _split(term)
        if name in ("a", "mx", "ptr", "exists"):
            total += 1
        elif name in ("include", "redirect") and value:
            total += 1
            key = value.lower()
            if key not in seen:
                seen.add(key)
                try:
                    nested = find_spf(await resolver.txt(value))
                except NoRecord:
                    nested = []
                if nested:
                    total += await count_lookups(nested[0], resolver, seen)
        if total > MAX_LOOKUPS:
            break
    return total


async def check_spf(domain: str, resolver: Resolver, required_include: str) -> RecordResult:
    suggestion = f"v=spf1 include:{required_include} ~all"
    try:
        records = find_spf(await resolver.txt(domain))
    except NoRecord:
        records = []
    except TemporaryDnsError:
        return RecordResult(Status.UNKNOWN, hint="DNS lookup failed temporarily; will retry.")

    if not records:
        return RecordResult(Status.MISSING, hint=f"No SPF record found. Publish: {suggestion}")
    if len(records) > 1:
        return RecordResult(
            Status.CONFLICT, found=" | ".join(records),
            hint="A domain may have only one SPF record. Merge them into one.",
        )

    record = records[0]
    parsed = [_split(t) for t in _terms(record)]
    includes = {v.lower() for _, n, v in parsed if n == "include" and v}
    if required_include.lower() not in includes:
        return RecordResult(
            Status.MISMATCH, found=record,
            hint=f"Add include:{required_include} to your existing record. Do not create a second one.",
        )
    qualifier = next((q for q, n, _ in parsed if n == "all"), None)
    if qualifier not in ("~", "-"):
        return RecordResult(Status.MISMATCH, found=record, hint="End the record with ~all or -all.")

    try:
        lookups = await count_lookups(record, resolver)
    except TemporaryDnsError:
        return RecordResult(Status.UNKNOWN, found=record, hint="Could not expand includes; will retry.")
    if lookups > MAX_LOOKUPS:
        return RecordResult(
            Status.CONFLICT, found=record,
            hint=f"{lookups} DNS lookups; the limit is {MAX_LOOKUPS}. Receivers will return a permanent SPF error.",
        )
    return RecordResult(Status.VALID, found=record)
