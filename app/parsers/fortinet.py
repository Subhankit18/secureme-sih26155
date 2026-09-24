from __future__ import annotations

import re
from typing import Any

from app.models import DeviceInfo, Evidence, NormalizedConfig


_SET = re.compile(r"^set\s+(\S+)\s+(.+)$", re.I)
_UNSET = re.compile(r"^unset\s+(\S+)(?:\s+.*)?$", re.I)
_EDIT = re.compile(r"^edit\s+(.+)$", re.I)
_CONFIG = re.compile(r"^config\s+(.+)$", re.I)

# These are generic FortiOS configuration keywords. They are intentionally
# treated as syntactically known without claiming that every command is a
# compliance control. Security observations are extracted separately below.
_KNOWN_SET_KEYS = {
    "hostname", "admin-ssh", "admin-telnet", "admin-sport", "admin-scp",
    "password-min-length", "status", "ip", "allowaccess", "alias",
    "type", "role", "vdom", "srcintf", "dstintf", "srcaddr", "dstaddr",
    "service", "action", "schedule", "logtraffic", "comments", "name",
    "interface", "mode", "server", "source-ip", "source-ip6", "port",
    "protocol", "version", "auth", "key", "community", "trap", "severity",
    "local-in-policy", "tcp-halfclose-timer", "tcp-timewait-timer",
}

_KNOWN_CONFIG_PREFIXES = (
    "system ", "log ", "firewall ", "router ", "vpn ", "user ", "user-group",
    "authentication ", "certificate ", "system", "switch-controller ",
    "wireless-controller ", "application-list ", "ips ", "antivirus ",
    "webfilter ", "dnsfilter ", "ssl-ssh-profile ", "voip-profile ",
    "virtual-wan-link", "endpoint-control ", "ha ", "router", "vpn",
)


def _clean_value(value: str) -> str:
    return value.strip().strip('"')


def parse_fortinet(text: str, analysis_id: str, source_file: str) -> NormalizedConfig:
    """Deterministically parse FortiOS hierarchical configuration.

    Supports repeated config/edit blocks, arbitrary nesting, set/unset commands,
    and large configurations in one linear pass. Only explicitly supported
    security observations are normalized; unsupported commands remain visible
    as evidence instead of being guessed.
    """
    controls: dict[str, Any] = {}
    unknown: list[Evidence] = []

    hostname: str | None = None
    ssh_enabled: bool | None = None
    telnet_enabled: bool | None = None
    password_min_length: int | None = None
    logging_enabled: bool | None = None

    # FortiOS uses config -> edit -> set -> next/end. Keep a stack so nested
    # blocks do not get confused when a 1000+ line file contains many sections.
    config_stack: list[str] = []
    edit_stack: list[str] = []

    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()

        m = _CONFIG.match(line)
        if m:
            section = m.group(1).strip().lower()
            config_stack.append(section)
            edit_stack.clear()
            continue

        if low == "end":
            if config_stack:
                config_stack.pop()
            edit_stack.clear()
            continue

        if low == "next":
            if edit_stack:
                edit_stack.pop()
            continue

        m = _EDIT.match(line)
        if m:
            edit_stack.append(_clean_value(m.group(1)))
            continue

        m = _SET.match(line)
        if m:
            key = m.group(1).lower()
            value = _clean_value(m.group(2))
            section = " / ".join(config_stack).lower()

            if section == "system global" and key == "hostname":
                hostname = value
                continue
            if section == "system global" and key == "admin-ssh" and value.lower() in {"enable", "disable"}:
                ssh_enabled = value.lower() == "enable"
                continue
            if section == "system global" and key == "admin-telnet" and value.lower() in {"enable", "disable"}:
                telnet_enabled = value.lower() == "enable"
                continue
            if section == "system admin" and key == "password-min-length":
                try:
                    password_min_length = int(value)
                    continue
                except ValueError:
                    pass
            if section == "log" and key == "status" and value.lower() in {"enable", "disable"}:
                logging_enabled = value.lower() == "enable"
                continue

            if key in _KNOWN_SET_KEYS:
                continue

            unknown.append(Evidence(line_number=idx, source=line))
            continue

        m = _UNSET.match(line)
        if m:
            key = m.group(1).lower()
            section = " / ".join(config_stack).lower()
            if section == "system global" and key == "admin-ssh":
                ssh_enabled = False
                continue
            if section == "system global" and key == "admin-telnet":
                telnet_enabled = False
                continue
            if section == "log" and key == "status":
                logging_enabled = False
                continue
            if key in _KNOWN_SET_KEYS:
                continue
            unknown.append(Evidence(line_number=idx, source=line))
            continue

        # Any other structural/standard FortiOS line is syntactically known.
        if low in {"show", "get", "diagnose", "execute", "abort"}:
            continue
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
