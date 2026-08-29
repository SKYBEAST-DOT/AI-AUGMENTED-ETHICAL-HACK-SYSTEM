SEVERITY_TO_SCORE = {
    "Informational": 10,
    "Low": 30,
    "Medium": 60,
    "High": 85,
    "Critical": 100,
}


def score_finding(
    *,
    severity: str,
    finding_name: str,
    description: str,
    evidence: str,
    affected_target: str,
    potential_impact: str,
    recommended_remediation: str,
    category: str,
) -> dict:
    normalized_severity = severity if severity in SEVERITY_TO_SCORE else "Informational"
    return {
        "finding_name": finding_name,
        "category": category,
        "severity": normalized_severity,
        "description": description,
        "evidence": evidence,
        "affected_target": affected_target,
        "potential_impact": potential_impact,
        "recommended_remediation": recommended_remediation,
        "score": SEVERITY_TO_SCORE[normalized_severity],
    }


def severity_distribution(findings: list[dict]) -> dict:
    distribution = {key: 0 for key in SEVERITY_TO_SCORE.keys()}
    for finding in findings:
        sev = finding.get("severity", "Informational")
        distribution[sev] = distribution.get(sev, 0) + 1
    return distribution
