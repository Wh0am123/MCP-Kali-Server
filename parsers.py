#!/usr/bin/env python3

# Output-parsing layer for MCP Kali Server.
#
# Turns raw tool stdout into structured JSON findings so MCP clients get small,
# consistent, queryable results instead of re-reading noisy text every run.
#
# Dependency-free on purpose: regex + light heuristics. A parser is a function
# (stdout: str) -> dict registered in PARSERS under the tool name. enrich()
# attaches the structured block under result["parsed"] and never touches the
# raw stdout/stderr already in the result.

import re
from typing import Any, Callable, Dict, List

logger_prefix = "[parsers]"


def parse_nmap(stdout: str) -> Dict[str, Any]:
    """Extract hosts, ports, services and versions from nmap human-readable output."""
    hosts: List[Dict[str, Any]] = []
    current: Dict[str, Any] = None

    # "Nmap scan report for scanme.nmap.org (45.33.32.156)" or "... for 10.0.0.1"
    host_re = re.compile(r"^Nmap scan report for (.+?)(?:\s+\(([\d.]+)\))?$")
    # "22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2"
    port_re = re.compile(
        r"^(\d+)/(tcp|udp)\s+(\w+)\s+([\w\-/?]+)(?:\s+(.*))?$"
    )
    os_re = re.compile(r"^(?:Running|OS details|Service Info):\s*(.+)$")

    for raw in stdout.splitlines():
        line = raw.rstrip()
        m = host_re.match(line.strip())
        if m:
            current = {
                "hostname": m.group(1) if m.group(2) else None,
                "address": m.group(2) or m.group(1),
                "ports": [],
                "os": None,
            }
            hosts.append(current)
            continue

        if current is None:
            continue

        m = port_re.match(line.strip())
        if m:
            current["ports"].append({
                "port": int(m.group(1)),
                "protocol": m.group(2),
                "state": m.group(3),
                "service": m.group(4),
                "version": (m.group(5) or "").strip() or None,
            })
            continue

        m = os_re.match(line.strip())
        if m and current.get("os") is None:
            current["os"] = m.group(1).strip()

    open_ports = [p for h in hosts for p in h["ports"] if p["state"] == "open"]
    return {
        "tool": "nmap",
        "hosts": hosts,
        "summary": {
            "hosts_found": len(hosts),
            "open_ports": len(open_ports),
        },
    }


def parse_nikto(stdout: str) -> Dict[str, Any]:
    """Extract target info and '+' findings from nikto output."""
    target = {"host": None, "ip": None, "port": None}
    findings: List[Dict[str, Any]] = []

    target_host_re = re.compile(r"^\+?\s*Target (?:Host|IP):\s*(.+)$")
    target_port_re = re.compile(r"^\+?\s*Target Port:\s*(\d+)$")
    # OSVDB or modern reference ids appearing inside a finding line.
    ref_re = re.compile(r"\b(OSVDB-\d+|CVE-\d{4}-\d+)\b")

    for raw in stdout.splitlines():
        line = raw.strip()

        m = target_host_re.match(line)
        if m:
            val = m.group(1).strip()
            if re.match(r"^[\d.]+$", val):
                target["ip"] = val
            else:
                target["host"] = val
            continue

        m = target_port_re.match(line)
        if m:
            target["port"] = int(m.group(1))
            continue

        # Findings are the "+ ..." lines that aren't banner/metadata noise.
        if line.startswith("+ ") and "Target" not in line and "Start Time" not in line:
            text = line[2:].strip()
            if not text or text.startswith(("Server:", "Retrieved", "Allowed HTTP")):
                # keep informational, but tag it low severity
                sev = "info"
            else:
                sev = "finding"
            findings.append({
                "text": text,
                "refs": ref_re.findall(text),
                "severity": sev,
            })

    return {
        "tool": "nikto",
        "target": target,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "with_refs": sum(1 for f in findings if f["refs"]),
        },
    }


def parse_gobuster(stdout: str) -> Dict[str, Any]:
    """Extract discovered paths/subdomains/vhosts from gobuster output (dir/dns/vhost modes)."""
    entries: List[Dict[str, Any]] = []

    # dir/vhost: "/admin  (Status: 301) [Size: 312] [--> http://x/admin/]"
    dir_re = re.compile(
        r"^(\S+)\s+\(Status:\s*(\d+)\)"
        r"(?:\s*\[Size:\s*(\d+)\])?"
        r"(?:\s*\[--> (.+?)\])?$"
    )
    # dns: "Found: sub.example.com"
    found_re = re.compile(r"^Found:\s*(.+?)(?:\s+\(Status:\s*(\d+)\).*)?$")

    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith(("=", "[+]", "Gobuster", "by ", "Progress:")):
            continue

        m = dir_re.match(line)
        if m:
            entries.append({
                "path": m.group(1),
                "status": int(m.group(2)),
                "size": int(m.group(3)) if m.group(3) else None,
                "redirect": m.group(4),
            })
            continue

        m = found_re.match(line)
        if m:
            entries.append({
                "path": m.group(1).strip(),
                "status": int(m.group(2)) if m.group(2) else None,
                "size": None,
                "redirect": None,
            })

    return {
        "tool": "gobuster",
        "entries": entries,
        "summary": {"total": len(entries)},
    }


def parse_dirb(stdout: str) -> Dict[str, Any]:
    """Extract found URLs and directories from dirb output."""
    entries: List[Dict[str, Any]] = []
    directories: List[str] = []

    # "+ http://x/admin (CODE:200|SIZE:1234)"
    url_re = re.compile(r"^\+\s*(\S+)\s*\(CODE:(\d+)\|SIZE:(\d+)\)")
    dir_re = re.compile(r"^==> DIRECTORY:\s*(\S+)")

    for raw in stdout.splitlines():
        line = raw.strip()

        m = url_re.match(line)
        if m:
            entries.append({
                "url": m.group(1),
                "status": int(m.group(2)),
                "size": int(m.group(3)),
            })
            continue

        m = dir_re.match(line)
        if m:
            directories.append(m.group(1))

    return {
        "tool": "dirb",
        "entries": entries,
        "directories": directories,
        "summary": {"urls": len(entries), "directories": len(directories)},
    }


def parse_sqlmap(stdout: str) -> Dict[str, Any]:
    """Extract injection points and back-end DBMS from sqlmap output."""
    injection_points: List[Dict[str, Any]] = []
    dbms: str = None
    current: Dict[str, Any] = None

    param_re = re.compile(r"^Parameter:\s*(.+?)\s*\((\w+)\)")
    type_re = re.compile(r"^\s*Type:\s*(.+)$")
    title_re = re.compile(r"^\s*Title:\s*(.+)$")
    dbms_re = re.compile(r"back-end DBMS(?:\s+is)?:?\s*(.+)$")

    for raw in stdout.splitlines():
        line = raw.rstrip()
        stripped = line.strip()

        m = param_re.match(stripped)
        if m:
            current = {
                "parameter": m.group(1),
                "location": m.group(2),
                "types": [],
                "titles": [],
            }
            injection_points.append(current)
            continue

        if current is not None:
            m = type_re.match(line)
            if m:
                current["types"].append(m.group(1).strip())
                continue
            m = title_re.match(line)
            if m:
                current["titles"].append(m.group(1).strip())
                continue

        m = dbms_re.search(stripped)
        if m and dbms is None:
            dbms = m.group(1).strip()

    return {
        "tool": "sqlmap",
        "injectable": len(injection_points) > 0,
        "dbms": dbms,
        "injection_points": injection_points,
        "summary": {"injection_points": len(injection_points)},
    }


def parse_wpscan(stdout: str) -> Dict[str, Any]:
    """Extract WordPress version, interesting findings, vulnerabilities and users from wpscan output."""
    wp_version: str = None
    findings: List[str] = []
    vulnerabilities: List[str] = []
    users: List[str] = []
    in_users = False

    version_re = re.compile(r"WordPress version ([\d.]+) identified")
    finding_re = re.compile(r"^\[\+\]\s*(.+)$")
    vuln_re = re.compile(r"^\[!\]\s*Title:\s*(.+)$")
    users_header_re = re.compile(r"User\(s\) Identified", re.IGNORECASE)

    for raw in stdout.splitlines():
        line = raw.strip()

        m = version_re.search(line)
        if m and wp_version is None:
            wp_version = m.group(1)

        if users_header_re.search(line):
            in_users = True
            continue

        m = vuln_re.match(line)
        if m:
            vulnerabilities.append(m.group(1).strip())
            continue

        m = finding_re.match(line)
        if m:
            text = m.group(1).strip()
            if in_users:
                users.append(text)
            else:
                findings.append(text)
            continue

        # a blank or non-[+] line ends the user block
        if in_users and not line.startswith(("[i]", "|")):
            in_users = False

    return {
        "tool": "wpscan",
        "wordpress_version": wp_version,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "users": users,
        "summary": {
            "findings": len(findings),
            "vulnerabilities": len(vulnerabilities),
            "users": len(users),
        },
    }


PARSERS: Dict[str, Callable[[str], Dict[str, Any]]] = {
    "nmap": parse_nmap,
    "nikto": parse_nikto,
    "gobuster": parse_gobuster,
    "dirb": parse_dirb,
    "sqlmap": parse_sqlmap,
    "wpscan": parse_wpscan,
}


def enrich(result: Dict[str, Any], tool: str) -> Dict[str, Any]:
    """Attach result['parsed'] for a known tool. Never raises, never alters raw output."""
    parser = PARSERS.get(tool)
    if parser is None:
        return result
    try:
        result["parsed"] = parser(result.get("stdout", "") or "")
    except Exception as e:  # parsing must never break the API response
        result["parsed"] = {"tool": tool, "error": f"parse failed: {e}"}
    return result
