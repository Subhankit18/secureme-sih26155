from __future__ import annotations

import re
from typing import Any

from app.models import DeviceInfo, Evidence, NormalizedConfig


def parse_cisco(text: str, analysis_id: str, source_file: str) -> NormalizedConfig:
    lines = text.splitlines()
    controls: dict[str, Any] = {}
    unknown: list[Evidence] = []

    hostname = None
    ssh_version = None
    telnet_enabled = None
    logging_enabled = None
    password_min_length = None

    for idx, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("!"):
            continue

        if re.match(r"^hostname\s+\S+", line, re.I):
            hostname = line.split(maxsplit=1)[1].strip()
            continue

        m = re.match(r"^ip\s+ssh\s+version\s+(\d+)", line, re.I)
        if m:
            ssh_version = int(m.group(1))
            continue

        m = re.match(r"^transport\s+input\s+(.+)$", line, re.I)
        if m:
            transports = m.group(1).lower().split()
            telnet_enabled = "telnet" in transports
            continue

        if re.match(r"^logging\s+host\s+\S+", line, re.I):
            logging_enabled = True
            continue

        m = re.match(r"^security\s+password\s+min-length\s+(\d+)", line, re.I)
        if m:
            password_min_length = int(m.group(1))
            continue

        known_prefixes = (
            "version ", "line ", "login", "exec-timeout", "service ",
            "enable secret", "username ", "interface ", "ip address ",
            "no shutdown", "description ", "access-list ",
        )
        if not line.lower().startswith(known_prefixes):
            unknown.append(Evidence(line_number=idx, source=line))

    if ssh_version is not None:
        controls["ssh_version"] = ssh_version
    if telnet_enabled is not None:
        controls["telnet_enabled"] = telnet_enabled
    if logging_enabled is not None:
        controls["logging_enabled"] = logging_enabled
    if password_min_length is not None:
        controls["password_min_length"] = password_min_length

    return NormalizedConfig(
        analysis_id=analysis_id,
        source_file=source_file,
        device=DeviceInfo(vendor="cisco", hostname=hostname),
        controls=controls,
        unknown_lines=unknown,
    )
