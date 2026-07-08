from pydantic import BaseModel, field_validator
from config import MAX_URLS_PER_REQUEST, MAX_BULK_TEXT_LENGTH


class LinkCheckRequest(BaseModel):
    urls: list[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v):
        if not v:
            raise ValueError("At least one URL is required")
        if len(v) > MAX_URLS_PER_REQUEST:
            raise ValueError(f"Maximum {MAX_URLS_PER_REQUEST} URLs per request")
        return v


class BulkTextRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def validate_text(cls, v):
        if len(v) > MAX_BULK_TEXT_LENGTH:
            raise ValueError(f"Text exceeds {MAX_BULK_TEXT_LENGTH} character limit")
        return v


class PhishingAnalysis(BaseModel):
    """Phishing analysis results for a single URL"""
    is_suspicious: bool
    risk_level: str
    phishing_score: int
    heuristic_flags: list[str]
    safe_browsing_threat: str | None
    virustotal_summary: str | None


class LinkResult(BaseModel):
    """Complete result for a checked link"""
    url: str
    status_code: int | None
    is_alive: bool
    response_time_ms: float | None
    redirect_url: str | None
    error: str | None
    ai_analysis: str | None
    phishing: PhishingAnalysis | None
    checked_at: str
