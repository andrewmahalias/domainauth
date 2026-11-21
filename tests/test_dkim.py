import asyncio

from app.domainauth.dkim import check_dkim, chunk_txt, generate_dkim_keypair, parse_tags
from app.domainauth.models import Status
from app.domainauth import TemporaryDnsError
from app.domainauth.testing import FakeResolver

HOST = "qeakflow._domainkey.example.de"


def check(zone, expected):
    return asyncio.run(check_dkim("example.de", "qeakflow", expected, FakeResolver(zone)))


def test_generated_key_round_trips_through_chunked_txt():
    _, value = generate_dkim_keypair()
    chunks = chunk_txt(value)
    assert len(chunks) > 1 and all(len(c) <= 255 for c in chunks)
    # the resolver joins character-strings, so publishing chunks must still verify
    assert check({HOST: ["".join(chunks)]}, value).status is Status.VALID


def test_whitespace_inside_key_is_ignored():
    r = check({HOST: ["v=DKIM1; k=rsa; p=AAAA BBBB CCCC"]}, "v=DKIM1; k=rsa; p=AAAABBBBCCCC")
    assert r.status is Status.VALID


def test_bare_base64_expected_value_works():
    assert check({HOST: ["v=DKIM1; p=AAAA"]}, "AAAA").status is Status.VALID


def test_different_key_is_mismatch():
    r = check({HOST: ["v=DKIM1; p=XXXX"]}, "v=DKIM1; p=AAAA")
    assert r.status is Status.MISMATCH


def test_missing_has_registrar_hint():
    r = check({}, "AAAA")
    assert r.status is Status.MISSING and "qeakflow._domainkey" in r.hint


def test_revoked_key():
    r = check({HOST: ["v=DKIM1; p="]}, "AAAA")
    assert r.status is Status.MISMATCH and "revoked" in r.hint


def test_surrounding_quotes_hint():
    r = check({HOST: ['"v=DKIM1; p=AAAA"']}, "AAAA")
    assert r.status is Status.MISMATCH and "quotes" in r.hint


def test_timeout_is_unknown():
    assert check({HOST: TemporaryDnsError("t")}, "AAAA").status is Status.UNKNOWN


def test_parse_tags():
    assert parse_tags("v=DKIM1; k=rsa; p=AA==") == {"v": "DKIM1", "k": "rsa", "p": "AA=="}
