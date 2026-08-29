import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]


def run_web_checks(target: str, timeout: int = 5) -> list[dict]:
    findings = []
    base_url = f"http://{target}"
    https_url = f"https://{target}"

    try:
        http_resp = requests.get(base_url, timeout=timeout, allow_redirects=True)
    except Exception as exc:
        return [
            {
                "name": "HTTP connection failure",
                "severity": "Informational",
                "description": "Could not perform HTTP-based checks.",
                "evidence": str(exc),
                "impact": "No direct risk identified; scan coverage reduced.",
                "remediation": "Confirm the target web service is reachable.",
                "category": "Security Misconfiguration",
            }
        ]

    try:
        https_resp = requests.get(https_url, timeout=timeout, allow_redirects=True)
        https_available = True
    except Exception:
        https_available = False
        https_resp = None

    if not https_available:
        findings.append(
            {
                "name": "HTTPS not available",
                "severity": "Medium",
                "description": "The service does not appear to support HTTPS.",
                "evidence": f"Unable to connect to {https_url}",
                "impact": "Traffic may be exposed to interception.",
                "remediation": "Enable TLS and redirect HTTP to HTTPS.",
                "category": "Cryptographic Failures",
            }
        )

    headers = dict(http_resp.headers)
    for header in SECURITY_HEADERS:
        if header not in headers:
            findings.append(
                {
                    "name": f"Missing security header: {header}",
                    "severity": "Low",
                    "description": f"{header} is not present in HTTP response headers.",
                    "evidence": "Observed response headers: " + ", ".join(sorted(headers.keys())),
                    "impact": "Reduced browser-side hardening controls.",
                    "remediation": f"Set the {header} header with recommended secure values.",
                    "category": "Security Misconfiguration",
                }
            )

    if "Server" in headers:
        findings.append(
            {
                "name": "Server banner disclosure",
                "severity": "Informational",
                "description": "Server header may reveal implementation details.",
                "evidence": f"Server: {headers.get('Server')}",
                "impact": "Can help attackers fingerprint technology stack.",
                "remediation": "Minimize unnecessary server banner exposure.",
                "category": "Security Misconfiguration",
            }
        )

    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie and ("Secure" not in set_cookie or "HttpOnly" not in set_cookie):
        findings.append(
            {
                "name": "Weak cookie flags",
                "severity": "Medium",
                "description": "Cookies may be missing Secure and/or HttpOnly flags.",
                "evidence": set_cookie[:400],
                "impact": "Cookies may be exposed to theft or script access.",
                "remediation": "Set Secure and HttpOnly (and SameSite where possible) on session cookies.",
                "category": "Identification and Authentication Failures",
            }
        )

    for path in ["/.git/", "/backup/", "/admin/", "/.env"]:
        try:
            r = requests.get(base_url + path, timeout=timeout)
            if r.status_code == 200:
                findings.append(
                    {
                        "name": f"Potential directory exposure: {path}",
                        "severity": "Medium",
                        "description": "A potentially sensitive path returned HTTP 200.",
                        "evidence": f"{base_url + path} returned status 200",
                        "impact": "Sensitive files or interfaces may be accessible.",
                        "remediation": "Restrict access or remove sensitive directories/files from web root.",
                        "category": "Broken Access Control",
                    }
                )
        except Exception:
            continue
    return findings
