
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
        r"sk-proj-[A-Za-z0-9_-]{12,}|"
        r"gh[pousr]_[A-Za-z0-9]{20,}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,}|"
        r"AKIA[A-Z0-9]{16})\b"
    ),
    "IPV4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "US_SSN": re.compile(r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}


def protect_sensitive_data(text: str) -> dict:
    findings = []
    protected_text = text

    for category, pattern in PATTERNS.items():
        matches = pattern.findall(protected_text)

        # Avoid classifying ordinary digit strings as payment cards unless they
        # pass the standard Luhn checksum.
        if category == "CREDIT_CARD":
            matches = [match for match in matches if _luhn_valid(match)]

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


def _luhn_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0
