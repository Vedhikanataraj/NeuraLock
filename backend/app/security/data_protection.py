
import re

PATTERNS = {
    "EMAIL": re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        re.IGNORECASE,
    ),
    "INDIAN_PHONE": re.compile(
        r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)"
    ),
    "API_KEY": re.compile(
        r"\b(?:sk-[A-Za-z0-9_-]{12,}|"
        r"AKIA[A-Z0-9]{16})\b"
    ),
}


def protect_sensitive_data(text: str) -> dict:
    findings = []
    protected_text = text

    for category, pattern in PATTERNS.items():
        matches = pattern.findall(protected_text)

        if matches:
            findings.append({
                "type": category,
                "count": len(matches),
            })
            protected_text = pattern.sub(
                f"[{category} REDACTED]",
                protected_text,
            )

    return {
        "text": protected_text,
        "detected": bool(findings),
        "findings": findings,
    }
