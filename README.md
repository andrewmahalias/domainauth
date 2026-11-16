# domainauth

Async SPF / DKIM / DMARC verification for sender domains. Built for a multi-tenant email platform
where every customer publishes DNS records and the platform must decide whether sending is safe.

![tests](https://github.com/<you>/domainauth/actions/workflows/ci.yml/badge.svg)

## Why it exists

Naive checks produce false failures. This library avoids the common ones:

| Naive check | What goes wrong | Here |
|---|---|---|
| `expected_spf in txt` | Any customer with an existing SPF record is marked "mismatch" | Parses the record, checks the provider `include:` and the `all` qualifier |
| Exact DMARC string | Every policy except one is "mismatch" | Accepts any valid policy, hints at `p=none` -> `quarantine` |
| Swallow every DNS error as "missing" | A timeout flips a verified domain to failed | `NXDOMAIN` is `missing`; timeout / SERVFAIL is `unknown` |
| Ignore the lookup limit | Receivers return a permanent SPF error | Counts lookups through `include`/`redirect`, flags more than 10 |
| One 2048-bit key in one TXT string | Exceeds 255 chars, registrar rejects it | `chunk_txt()` splits it; the resolver joins it back |

## Usage

```python
from domainauth import DnsPythonResolver, generate_dkim_keypair, verify_domain

private_pem, dkim_value = generate_dkim_keypair()
report = await verify_domain(
    "example.de", DnsPythonResolver(),
    spf_include="spf.provider.example", dkim_selector="selector1", dkim_expected=dkim_value,
)
report.sending_ready   # SPF and DKIM valid. DMARC is advisory.
report.spf.status, report.spf.hint
```

Statuses: `valid`, `missing`, `mismatch`, `conflict`, `unknown`. Every failure carries a specific hint.

## Design

- The resolver is a `Protocol`. Production uses `DnsPythonResolver` (public resolvers, not the host's);
  tests use `FakeResolver` with an in-memory zone, so the suite needs no network.
- `unknown` means retry later. Callers decide the backoff; the library never turns a timeout into a failure.

## Not included

Scheduling and backoff, persistence of results, org-domain DMARC fallback for subdomains,
SPF macros and `ip4`/`ip6` matching. DKIM signing itself is the sending provider's job; this library only
generates a key pair and verifies the published record.

## Develop

```
pip install -e ".[dev]" && pytest
```
