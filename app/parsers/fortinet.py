from __future__ import annotations

import re
from typing import Any

from app.models import DeviceInfo, Evidence, NormalizedConfig


def parse_fortinet(text: str, analysis_id: str, source_file: str) -> NormalizedConfig:
    lines = text.splitlines()
    controls: dict[str, Any] = {}
    unknown: list[Evidence] = []

    hostname = None
    ssh_enabled = None
    telnet_enabled = None
    password_min_length = None
    logging_enabled = None

    in_global = False
    in_admin = False
    in_log = False

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line:
            continue

        lower = line.lower()

        if lower == "config system global":
            in_global, in_admin, in_log = True, False, False
            continue

        if lower == "config system admin":
            in_global, in_admin, in_log = False, True, False
            continue

        if lower == "config log":
            in_global, in_admin, in_log = False, False, True
            continue

        if lower == "end":
            in_global = in_admin = in_log = False
            continue

        if in_global:
            m = re.match(r"set\s+hostname\s+(.+)$", line, re.I)
            if m:
                hostname = m.group(1).strip().strip('"')
                continue

            m = re.match(r"set\s+admin-ssh\s+(enable|disable)", line, re.I)
            if m:
                ssh_enabled = m.group(1).lower() == "enable"
                continue

            m = re.match(r"set\s+admin-telnet\s+(enable|disable)", line, re.I)
            if m:
                telnet_enabled = m.group(1).lower() == "enable"
                continue

        elif in_admin:
            m = re.match(r"set\s+password-min-length\s+(\d+)", line, re.I)
            if m:
                password_min_length = int(m.group(1))
                continue

        elif in_log:
            m = re.match(r"set\s+status\s+(enable|disable)", line, re.I)
            if m:
                logging_enabled = m.group(1).lower() == "enable"
                continue

        if lower.startswith(("set ", "config ", "edit ")):
            unknown.append(Evidence(line_number=idx, source=line))

    if ssh_enabled is not None:
        controls["ssh_enabled"] = ssh_enabled
    if telnet_enabled is not None:
        controls["telnet_enabled"] = telnet_enabled
    if password_min_length is not None:
        controls["password_min_length"] = password_min_length
    if logging_enabled is not None:
        controls["logging_enabled"] = logging_enabled

    return NormalizedConfig(
        analysis_id=analysis_id,
        source_file=source_file,
        device=DeviceInfo(vendor="fortinet", hostname=hostname),
        controls=controls,
        unknown_lines=unknown,
    )
