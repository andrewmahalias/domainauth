import base64
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .models import RecordResult, Status
from .resolver import NoRecord, Resolver, TemporaryDnsError


def generate_dkim_keypair(bits: int = 2048) -> tuple[str, str]:
    """Return (private_key_pem, dns_txt_value)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"


def chunk_txt(value: str, size: int = 255) -> list[str]:
    """A 2048-bit key exceeds the 255-char limit of one TXT string; DNS UIs need chunks."""
    return [value[i:i + size] for i in range(0, len(value), size)]


def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def _compact(s: str) -> str:
    return re.sub(r"\s+", "", s)


async def check_dkim(domain: str, selector: str, expected: str, resolver: Resolver) -> RecordResult:
    """`expected` is either the bare base64 key or the full 'v=DKIM1; ...; p=...' value."""
    expected_p = _compact(parse_tags(expected).get("p", expected))
    host = f"{selector}._domainkey.{domain}"
    try:
        txts = await resolver.txt(host)
    except NoRecord:
        return RecordResult(
            Status.MISSING,
            hint=f"No record at {host}. Many registrars append the domain automatically, "
                 f"so enter `{selector}._domainkey`, not the full name.",
        )
    except TemporaryDnsError:
        return RecordResult(Status.UNKNOWN, hint="DNS lookup failed temporarily; will retry.")

    if any(t.strip().startswith('"') for t in txts):
        return RecordResult(Status.MISMATCH, found=txts[0], hint="Remove the surrounding quotes from the value.")

    for txt in txts:
        tags = parse_tags(txt)
        if tags.get("v", "DKIM1").upper() != "DKIM1" or "p" not in tags:
            continue
        found_p = _compact(tags["p"])
        if not found_p:
            return RecordResult(Status.MISMATCH, found=txt, hint="This key is revoked (empty p=).")
        if found_p == expected_p:
            return RecordResult(Status.VALID, found=txt)
        return RecordResult(Status.MISMATCH, found=txt, hint="The published key differs from the one we generated.")
    return RecordResult(Status.MISSING, hint=f"{host} exists but holds no DKIM key.")
