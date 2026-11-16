from fastapi import APIRouter, HTTPException
from .schemas import VerifyRequest
from app.domainauth.resolver import DnsPythonResolver
from app.domainauth.verify import verify_domain

router = APIRouter()


@router.post("/verify")
async def api_verify_domain(payload: VerifyRequest):
    resolver = DnsPythonResolver()
    try:
        report = await verify_domain(
            domain=payload.domain,
            resolver=resolver,
            spf_include=payload.spf_include,
            dkim_selector=payload.dkim_selector,
            dkim_expected=payload.dkim_expected,
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))