from dataclasses import asdict

from fastapi import APIRouter, Depends

from .config import Settings, get_settings
from .schemas import VerifyRequest
from app.domainauth.resolver import DnsPythonResolver
from app.domainauth.verify import verify_domain

router = APIRouter()


@router.post("/verify")
async def api_verify_domain(
    payload: VerifyRequest,
    settings: Settings = Depends(get_settings),
):
    resolver = DnsPythonResolver(
        nameservers=tuple(settings.dns_nameservers),
        timeout=settings.dns_timeout,
    )
    report = await verify_domain(
        domain=payload.domain,
        resolver=resolver,
        spf_include=payload.spf_include,
        dkim_selector=payload.dkim_selector,
        dkim_expected=payload.dkim_expected,
    )
    return {
        **asdict(report),
        "sending_ready": report.sending_ready,
    }