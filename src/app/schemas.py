from pydantic import BaseModel, Field


class VerifyRequest(BaseModel):
    domain: str = Field(..., example="example.com")
    spf_include: str = Field(..., example="mail.example.com")
    dkim_selector: str = Field("default", example="default")
    dkim_expected: str = Field(..., example="v=DKIM1; k=rsa; p=MIIBIjAN...")
