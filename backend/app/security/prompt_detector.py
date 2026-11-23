
import re
import unicodedata

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
    ("INJ-005", re.compile(r"\b(?:act|pretend)\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|developer|system)\b", re.I)),
    ("INJ-006", re.compile(r"\b(?:show|dump|repeat|quote)\b.{0,60}\b(?:hidden|internal|system)\b.{0,30}\b(?:prompt|instructions?|message)\b", re.I)),
    ("INJ-007", re.compile(r"\b(?:ignore|disregard|override)\b.{0,60}\b(?:safety|security|policy|guardrails?)\b", re.I)),
    ("INJ-008", re.compile(r"\b(?:execute|run)\b.{0,50}\b(?:shell|command|code)\b.{0,50}\b(?:without|bypass|approval)\b", re.I)),
    ("INJ-009", re.compile(r"\b(?:exfiltrate|leak|send|forward)\b.{0,80}\b(?:document|conversation|credential|private|confidential|personal)\b", re.I)),
    ("INJ-010", re.compile(r"\b(?:new instruction|system override|developer mode|jailbreak)\b", re.I)),
]


def inspect_prompt(text: str) -> dict:
    # Normalize compatibility characters and remove zero-width formatting marks
    # before matching common obfuscated variants.
    normalized = unicodedata.normalize("NFKC", text)
    normalized = "".join(
        char for char in normalized
        if unicodedata.category(char) not in {"Cf", "Cc"} or char in "\n\t"
    )
    for rule_id, pattern in RULES:
        if pattern.search(normalized):
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
