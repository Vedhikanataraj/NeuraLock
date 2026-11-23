"""Evaluate the prompt detector against a labeled JSONL file.

Each row must have {"text": "...", "injection": true|false}.
Run: python ml/evaluate_security.py path/to/evaluation.jsonl
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.security.prompt_detector import inspect_prompt  # noqa: E402


def evaluate(path: Path) -> dict:
    tp = fp = tn = fn = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row.get("text"), str) or not isinstance(row.get("injection"), bool):
            raise ValueError(f"Line {line_number} needs string text and boolean injection fields")
        predicted, actual = bool(inspect_prompt(row["text"])["blocked"]), row["injection"]
        if predicted and actual: tp += 1
        elif predicted: fp += 1
        elif actual: fn += 1
        else: tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "samples": tp + fp + tn + fn,
        "true_positive": tp, "false_positive": fp,
        "true_negative": tn, "false_negative": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python ml/evaluate_security.py evaluation.jsonl")
    print(json.dumps(evaluate(Path(sys.argv[1])), indent=2))
