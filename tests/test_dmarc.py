import asyncio

from domainauth.dmarc import check_dmarc
from domainauth.models import Status
from domainauth.resolver import TemporaryDnsError
from domainauth.testing import FakeResolver


def check(zone):
    return asyncio.run(check_dmarc("example.de", FakeResolver(zone)))


def test_any_existing_policy_is_valid():
    """The old exact-string comparison marked everything but one policy as mismatch."""
    for policy in ("none", "quarantine", "reject"):
        assert check({"_dmarc.example.de": [f"v=DMARC1; p={policy}; pct=50"]}).status is Status.VALID


def test_p_none_carries_a_hint():
    assert "Tighten" in check({"_dmarc.example.de": ["v=DMARC1; p=none"]}).hint


def test_missing_suggests_starter_record():
    r = check({})
    assert r.status is Status.MISSING and "p=none" in r.hint


def test_invalid_policy():
    assert check({"_dmarc.example.de": ["v=DMARC1; p=bogus"]}).status is Status.MISMATCH


def test_two_records_conflict():
    assert check({"_dmarc.example.de": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]}).status is Status.CONFLICT


def test_timeout_is_unknown():
    assert check({"_dmarc.example.de": TemporaryDnsError("t")}).status is Status.UNKNOWN
