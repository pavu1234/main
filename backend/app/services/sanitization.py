import re

_PATTERNS = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)([^\s]+)"), r"\1************"),
    (re.compile(r"(?i)(cookie:\s*)(.+)"), r"\1************"),
    (re.compile(r"(?i)(set-cookie:\s*)(.+)"), r"\1************"),
    (re.compile(r"(?i)(password|passwd|pwd)(\s*[:=]\s*)([^\s&;]+)"), r"\1\2************"),
    (re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"), "eyJ************"),
    (re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{8,})\b"), "sk_************"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "[REDACTED PRIVATE KEY]"),
]

def redact(value: str) -> str:
    out = value or ""
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out[:12000]
