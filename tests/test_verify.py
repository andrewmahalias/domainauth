import asyncio

from app.domainauth import verify_domain
from app.domainauth import TemporaryDnsError
from app.domainauth.testing import FakeResolver

KW = dict(spf_include="spf.provider.example", dkim_selector="qeakflow", dkim_expected="AAAA")


def report(zone):
    return asyncio.run(verify_domain("example.de", FakeResolver(zone), **KW))


GOOD = {
    "example.de": ["v=spf1 include:spf.provider.example ~all"],
    "qeakflow._domainkey.example.de": ["v=DKIM1; k=rsa; p=AAAA"],
}


def test_sending_ready_without_dmarc():
    r = report(GOOD)
    assert r.sending_ready and r.dmarc.status.value == "missing"


def test_not_ready_when_dkim_missing():
    assert not report({"example.de": GOOD["example.de"]}).sending_ready


def test_a_timeout_never_counts_as_ready():
    zone = {**GOOD, "qeakflow._domainkey.example.de": TemporaryDnsError("t")}
    r = report(zone)
    assert not r.sending_ready and r.dkim.status.value == "unknown"
