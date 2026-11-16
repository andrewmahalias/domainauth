import asyncio

from domainauth.models import Status
from domainauth.resolver import TemporaryDnsError
from domainauth.spf import check_spf, count_lookups
from domainauth.testing import FakeResolver

INC = "spf.provider.example"


def run(coro):
    return asyncio.run(coro)


def spf(zone):
    return run(check_spf("example.de", FakeResolver(zone), INC))


def test_valid_when_provider_included_and_soft_fail():
    r = spf({"example.de": [f"v=spf1 include:{INC} ~all"]})
    assert r.status is Status.VALID


def test_existing_record_with_other_includes_is_valid():
    """The old `expected in txt` check marked this as mismatch."""
    r = spf({"example.de": [f"v=spf1 include:_spf.google.com include:{INC} -all"],
             "_spf.google.com": ["v=spf1 ip4:1.2.3.4 ~all"]})
    assert r.status is Status.VALID


def test_missing_gives_suggested_record():
    r = spf({})
    assert r.status is Status.MISSING and f"include:{INC}" in r.hint


def test_two_spf_records_conflict():
    r = spf({"example.de": ["v=spf1 include:a.example ~all", f"v=spf1 include:{INC} ~all"]})
    assert r.status is Status.CONFLICT and "one SPF record" in r.hint


def test_other_txt_records_are_ignored():
    r = spf({"example.de": ["google-site-verification=abc", f"v=spf1 include:{INC} ~all"]})
    assert r.status is Status.VALID


def test_missing_include_is_mismatch_with_merge_hint():
    r = spf({"example.de": ["v=spf1 include:_spf.google.com ~all"], "_spf.google.com": ["v=spf1 ~all"]})
    assert r.status is Status.MISMATCH and "second one" in r.hint


def test_plus_all_or_no_all_is_mismatch():
    assert spf({"example.de": [f"v=spf1 include:{INC} +all"]}).status is Status.MISMATCH
    assert spf({"example.de": [f"v=spf1 include:{INC}"]}).status is Status.MISMATCH
    assert spf({"example.de": [f"v=spf1 include:{INC} ?all"]}).status is Status.MISMATCH


def test_over_ten_lookups_is_conflict():
    mechs = " ".join(["a"] * 10)
    r = spf({"example.de": [f"v=spf1 include:{INC} {mechs} ~all"], INC: ["v=spf1 ip4:1.2.3.4 -all"]})
    assert r.status is Status.CONFLICT and "limit is 10" in r.hint


def test_nested_includes_are_counted():
    zone = {"example.de": [f"v=spf1 include:{INC} include:a.example ~all"],
            INC: ["v=spf1 ~all"],
            "a.example": ["v=spf1 include:b.example mx ~all"],
            "b.example": ["v=spf1 a a a a a a a ~all"]}
    # include(inc)=1, include(a)=1, nested include(b)=1, mx=1, 7x a = 11
    assert run(count_lookups(zone["example.de"][0], FakeResolver(zone))) > 10
    assert spf(zone).status is Status.CONFLICT


def test_include_loop_terminates():
    zone = {"example.de": [f"v=spf1 include:{INC} ~all"],
            INC: ["v=spf1 include:loop.example ~all"],
            "loop.example": [f"v=spf1 include:{INC} ~all"]}
    assert spf(zone).status is Status.VALID


def test_timeout_is_unknown_not_missing():
    r = spf({"example.de": TemporaryDnsError("timeout")})
    assert r.status is Status.UNKNOWN


def test_timeout_while_expanding_includes_is_unknown():
    r = spf({"example.de": [f"v=spf1 include:{INC} ~all"], INC: TemporaryDnsError("servfail")})
    assert r.status is Status.UNKNOWN
