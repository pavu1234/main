WEIGHTS = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
def calculate_score(findings: list[dict]) -> int:
    deduction = sum(WEIGHTS.get(f.get("severity", "INFO"), 0) for f in findings)
    return max(0, 100 - min(100, deduction))
