import ipaddress
import socket
from urllib.parse import urlparse


def normalize_target(raw_target: str) -> str:
    target = (raw_target or "").strip().lower()
    if not target:
        raise ValueError("Target is required.")
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or target
    if not host:
        raise ValueError("Unable to parse target host.")
    return host


def _is_private_or_local_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def is_default_safe_target(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    if _is_private_or_local_ip(host):
        return True
    if host.endswith(".local"):
        return True

    try:
        resolved_ip = socket.gethostbyname(host)
        return _is_private_or_local_ip(resolved_ip)
    except Exception:
        return False


def validate_authorized_target(raw_target: str, explicitly_authorized: bool) -> tuple[str, bool]:
    host = normalize_target(raw_target)
    default_safe = is_default_safe_target(host)
    if not default_safe and not explicitly_authorized:
        raise ValueError(
            "Public targets require explicit authorization confirmation. "
            "Only scan targets you are permitted to test."
        )
    return host, default_safe or explicitly_authorized
