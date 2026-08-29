import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


def _url(target: str, scheme: str) -> str:
    return f"{scheme}://{target}"


def run_reconnaissance(target: str, timeout: int = 5) -> dict:
    results = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dns": {},
        "http": {},
        "https": {},
        "robots_txt": None,
        "headers": {},
        "certificate": {},
        "errors": [],
    }
    try:
        ip = socket.gethostbyname(target)
        results["dns"]["resolved_ip"] = ip
        try:
            results["dns"]["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            results["dns"]["reverse_dns"] = "Unavailable"
    except Exception as exc:
        results["errors"].append(f"DNS resolution failed: {exc}")

    for scheme in ("http", "https"):
        url = _url(target, scheme)
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            results[scheme] = {
                "available": True,
                "status_code": resp.status_code,
                "final_url": resp.url,
            }
            if not results["headers"]:
                results["headers"] = dict(resp.headers)
        except Exception:
            results[scheme] = {"available": False}

    try:
        robots = requests.get(_url(target, "http") + "/robots.txt", timeout=timeout)
        if robots.status_code == 200:
            results["robots_txt"] = robots.text[:2000]
    except Exception:
        pass

    if results["https"].get("available"):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as secure_sock:
                    cert = secure_sock.getpeercert()
            results["certificate"] = {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
            }
        except Exception as exc:
            results["errors"].append(f"Certificate inspection failed: {exc}")
    return results
