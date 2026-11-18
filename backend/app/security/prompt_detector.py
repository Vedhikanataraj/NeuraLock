
import re

RULES = [
    (
        "INJ-001",
        re.compile(
            r"\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b",
            re.IGNORECASE,
        ),
    ),
    (
        "INJ-002",
        re.compile(
            r"\b(?:reveal|disclose|print)\s+(?:the\s+)?"
            r"(?:system prompt|password|secret|api key)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "INJ-003",
        re.compile(
            r"\b(?:bypass|disable)\s+(?:all\s+)?"
            r"(?:security|safety)\s+(?:rules|checks|controls)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "INJ-004",
        re.compile(
            r"\b(?:send|exfiltrate|leak)\b.{0,100}"
            r"\bconfidential data\b",
            re.IGNORECASE,
        ),
    ),
]


def inspect_prompt(text: str) -> dict:
    for rule_id, pattern in RULES:
        if pattern.search(text):
            return {
                "blocked": True,
                "risk": "high",
                "rule_id": rule_id,
                "reason": "Suspicious instruction matched a security rule.",
            }

    return {
        "blocked": False,
        "risk": "low",
        "rule_id": None,
        "reason": "No configured detection rule matched.",
    }
