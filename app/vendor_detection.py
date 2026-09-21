from __future__ import annotations

import re
from app.models import VendorDetection


def detect_vendor(text: str) -> VendorDetection:
    lines = text.splitlines()
    lower = text.lower()

    cisco_patterns = [
        (r"^\s*version\s+\d", "Cisco-style version header"),
        (r"^\s*line\s+vty\s+\d+", "Cisco VTY configuration"),
        (r"^\s*transport\s+input\s+", "Cisco transport input command"),
        (r"^\s*ip\s+ssh\s+version\s+\d+", "Cisco SSH version command"),
        (r"^\s*logging\s+host\s+\S+", "Cisco logging host command"),
    ]

    fortinet_patterns = [
        (r"^\s*config\s+system\s+global", "Fortinet system global block"),
        (r"^\s*set\s+hostname\s+\S+", "Fortinet hostname command"),
        (r"^\s*config\s+system\s+admin", "Fortinet admin configuration"),
        (r"^\s*set\s+admin-sport\s+\d+", "Fortinet admin service setting"),
        (r"^\s*set\s+admin-scp\s+", "Fortinet admin SCP setting"),
        (r"^\s*config\s+log", "Fortinet logging configuration"),
    ]

    cisco_hits = []
    for pattern, label in cisco_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE):
            cisco_hits.append(label)

    fortinet_hits = []
    for pattern, label in fortinet_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE):
            fortinet_hits.append(label)

    cisco_score = len(cisco_hits)
    fortinet_score = len(fortinet_hits)

    if cisco_score == 0 and fortinet_score == 0:
        return VendorDetection(
            vendor="unknown",
            confidence=0.0,
            method="deterministic",
            evidence=[],
        )

    if cisco_score == fortinet_score:
        return VendorDetection(
            vendor="ambiguous",
            confidence=0.5,
            method="deterministic",
            evidence=cisco_hits + fortinet_hits,
        )

    if cisco_score > fortinet_score:
        confidence = min(0.99, 0.60 + 0.08 * cisco_score)
        return VendorDetection(
            vendor="cisco",
            confidence=round(confidence, 2),
            method="deterministic",
            evidence=cisco_hits,
        )

    confidence = min(0.99, 0.60 + 0.08 * fortinet_score)
    return VendorDetection(
        vendor="fortinet",
        confidence=round(confidence, 2),
        method="deterministic",
        evidence=fortinet_hits,
    )
