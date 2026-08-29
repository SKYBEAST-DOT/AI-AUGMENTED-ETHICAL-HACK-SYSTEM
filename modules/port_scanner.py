import re
import shutil
import socket
import subprocess

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]


def _safe_socket_scan(target: str, ports: list[int], timeout: float = 0.5):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((target, port)) == 0:
                service = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
                open_ports.append({"port": port, "service": service, "version": "unknown"})
    return open_ports


def _nmap_scan(target: str, intensity: str) -> list[dict]:
    if intensity == "high":
        args = ["nmap", "-sV", "--top-ports", "200", target]
    elif intensity == "medium":
        args = ["nmap", "-sV", "--top-ports", "100", target]
    else:
        args = ["nmap", "-sV", "--top-ports", "30", target]

    proc = subprocess.run(args, capture_output=True, text=True, timeout=120, check=False)
    output = proc.stdout
    open_ports = []
    for line in output.splitlines():
        match = re.search(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line)
        if match:
            open_ports.append(
                {
                    "port": int(match.group(1)),
                    "service": match.group(2),
                    "version": match.group(3).strip() or "unknown",
                }
            )
    return open_ports


def run_port_scan(target: str, intensity: str = "low") -> dict:
    supported_levels = {"low", "medium", "high"}
    if intensity not in supported_levels:
        intensity = "low"
    nmap_available = bool(shutil.which("nmap"))
    if nmap_available:
        try:
            ports = _nmap_scan(target, intensity)
            return {"engine": "nmap", "open_ports": ports, "error": None}
        except Exception as exc:
            return {"engine": "nmap", "open_ports": [], "error": str(exc)}
    ports = _safe_socket_scan(target, COMMON_PORTS)
    return {"engine": "socket_fallback", "open_ports": ports, "error": None}
