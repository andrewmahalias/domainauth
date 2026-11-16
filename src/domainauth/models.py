from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    VALID = "valid"
    MISSING = "missing"      # definitive "no such record"
    MISMATCH = "mismatch"    # record exists but is wrong
    CONFLICT = "conflict"    # e.g. two SPF records, or over the 10-lookup limit
    UNKNOWN = "unknown"      # timeout / SERVFAIL: retry, never treat as failure


@dataclass(frozen=True)
class RecordResult:
    status: Status
    found: str | None = None
    hint: str | None = None


@dataclass(frozen=True)
class DomainReport:
    domain: str
    spf: RecordResult
    dkim: RecordResult
    dmarc: RecordResult

    @property
    def sending_ready(self) -> bool:
        """SPF and DKIM gate sending. DMARC is advisory."""
        return self.spf.status is Status.VALID and self.dkim.status is Status.VALID
