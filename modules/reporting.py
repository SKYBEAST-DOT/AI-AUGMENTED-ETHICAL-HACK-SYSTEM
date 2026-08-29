from datetime import datetime, timezone
from pathlib import Path


DISCLAIMER = (
    "This report is generated for authorized security testing only. "
    "Automated findings are indicators and require manual verification."
)


def generate_html_report(target: str, scan_summary: dict, findings: list[dict], output_dir: str = "reports") -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"assessment_{target.replace('.', '_')}_{timestamp}.html"
    findings_rows = "".join(
        f"""
        <tr>
          <td>{f['finding_name']}</td>
          <td>{f['category']}</td>
          <td>{f['severity']}</td>
          <td>{f['score']}</td>
          <td>{f['evidence']}</td>
          <td>{f['potential_impact']}</td>
          <td>{f['recommended_remediation']}</td>
        </tr>
        """
        for f in findings
    )
    html = f"""
    <html>
      <head><title>Security Assessment Report - {target}</title></head>
      <body>
        <h1>Ethical Hacking & Vulnerability Assessment Report</h1>
        <h2>Executive Summary</h2>
        <p>Target: {target}</p>
        <p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
        <p>{DISCLAIMER}</p>
        <h2>Methodology</h2>
        <p>Reconnaissance → Enumeration → Vulnerability Assessment → Risk Rating → Analysis</p>
        <h2>Target Information</h2>
        <pre>{scan_summary}</pre>
        <h2>Findings</h2>
        <table border="1" cellpadding="6" cellspacing="0">
          <tr>
            <th>Finding</th><th>OWASP Category</th><th>Severity</th><th>Score</th>
            <th>Evidence</th><th>Impact</th><th>Recommendation</th>
          </tr>
          {findings_rows}
        </table>
        <h2>Disclaimer</h2>
        <p>{DISCLAIMER}</p>
      </body>
    </html>
    """
    path.write_text(html, encoding="utf-8")
    return str(path)
