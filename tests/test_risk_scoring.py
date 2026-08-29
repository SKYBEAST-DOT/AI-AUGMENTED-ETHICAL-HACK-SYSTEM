from modules.risk_scoring import score_finding, severity_distribution


def test_score_finding_uses_transparent_mapping():
    finding = score_finding(
        severity="High",
        finding_name="Test finding",
        description="desc",
        evidence="evidence",
        affected_target="localhost",
        potential_impact="impact",
        recommended_remediation="fix",
        category="Security Misconfiguration",
    )
    assert finding["score"] == 85
    assert finding["severity"] == "High"


def test_severity_distribution_counts_findings():
    dist = severity_distribution(
        [
            {"severity": "Low"},
            {"severity": "Low"},
            {"severity": "Critical"},
        ]
    )
    assert dist["Low"] == 2
    assert dist["Critical"] == 1
