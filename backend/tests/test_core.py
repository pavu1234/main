import pytest
from app.scanner.scope import normalize_url, validate_public_target, ScopeError, same_host
from app.services.sanitization import redact
from app.services.scoring import calculate_score
from app.scanner.checks.headers import check as header_check

def test_normalize(): assert normalize_url("https://Example.COM") == "https://example.com/"
def test_scope(): assert same_host("https://example.com/a","https://example.com/b") and not same_host("https://example.com","https://evil.com")
@pytest.mark.asyncio
async def test_ssrf_localhost():
    with pytest.raises(ScopeError): await validate_public_target("http://127.0.0.1")
def test_redaction(): assert "secret" not in redact("Authorization: Bearer secret")
def test_scoring(): assert calculate_score([{"severity":"HIGH"},{"severity":"MEDIUM"}]) == 85
def test_headers(): assert any(f["title"].startswith("Missing Content") for f in header_check("https://example.com",{},True))
