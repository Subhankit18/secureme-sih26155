from __future__ import annotations

import re
from typing import Any

from app.models import DeviceInfo, Evidence, NormalizedConfig


# Cisco IOS/IOS-XE hardening-oriented deterministic parser.
# The parser is intentionally syntax-focused: it extracts security-relevant
# observations, preserves source evidence, and never makes compliance decisions.

RE_LINE = re.compile(r"^line\s+(?P<kind>vty|console|con|aux|tty)\b(?P<args>.*)$", re.I)
RE_IF = re.compile(r"^interface\s+(?P<name>\S+)", re.I)
RE_ROUTER = re.compile(r"^router\s+(?P<proto>\S+)(?:\s+(?P<args>.*))?$", re.I)
RE_HOSTNAME = re.compile(r"^hostname\s+(\S+)", re.I)
RE_VERSION = re.compile(r"^version\s+(.+)$", re.I)
RE_NUM = re.compile(r"^(?:security\s+passwords|security\s+password)\s+min-length\s+(\d+)$", re.I)
RE_SSH = re.compile(r"^ip\s+ssh\s+version\s+(\d+)$", re.I)
RE_SSH_TIMEOUT = re.compile(r"^ip\s+ssh\s+time-out\s+(\d+)$", re.I)
RE_SSH_RETRIES = re.compile(r"^ip\s+ssh\s+authentication-retries\s+(\d+)$", re.I)
RE_LOG_HOST = re.compile(r"^logging\s+host\s+(\S+)", re.I)
RE_LOG_TRAP = re.compile(r"^logging\s+trap(?:\s+(\S+))?", re.I)
RE_LOG_BUF = re.compile(r"^logging\s+buffered\b(?:\s+(.*))?$", re.I)
RE_LOG_SOURCE = re.compile(r"^logging\s+source-interface\s+(\S+)", re.I)
RE_EXEC = re.compile(r"^exec-timeout\s+(\d+)(?:\s+(\d+))?", re.I)
RE_TRANSPORT_IN = re.compile(r"^transport\s+input\s+(.+)$", re.I)
RE_ACCESS_CLASS = re.compile(r"^access-class\s+(\S+)\s+(in|out)\b", re.I)
RE_IPV6_ACCESS = re.compile(r"^ipv6\s+access-class\s+(\S+)\s+(in|out)\b", re.I)
RE_LOGIN_AUTH = re.compile(r"^login\s+authentication\s+(\S+)", re.I)
RE_LOGIN_BLOCK = re.compile(r"^login\s+block-for\s+(\d+)\s+attempts\s+(\d+)\s+within\s+(\d+)", re.I)
RE_LOGIN_DELAY = re.compile(r"^login\s+delay\s+(\d+)", re.I)
RE_AAA_LOGIN = re.compile(r"^aaa\s+authentication\s+login\s+(\S+)\s+(.+)$", re.I)
RE_AAA_AUTHZ_EXEC = re.compile(r"^aaa\s+authorization\s+exec\s+(\S+)\s+(.+)$", re.I)
RE_AAA_AUTHZ_CMD = re.compile(r"^aaa\s+authorization\s+commands\s+(\d+)\s+(\S+)\s+(.+)$", re.I)
RE_AAA_ACCT_EXEC = re.compile(r"^aaa\s+accounting\s+exec\s+(\S+)\s+(.+)$", re.I)
RE_AAA_ACCT_CMD = re.compile(r"^aaa\s+accounting\s+commands\s+(\d+)\s+(\S+)\s+(.+)$", re.I)
RE_TACACS_SERVER = re.compile(r"^tacacs\s+server\s+(\S+)", re.I)
RE_TACACS_HOST = re.compile(r"^tacacs-server\s+host\s+(\S+)", re.I)
RE_RADIUS_HOST = re.compile(r"^radius-server\s+host\s+(\S+)", re.I)
RE_USERNAME = re.compile(r"^username\s+(\S+)\s+(password|secret)(?:\s+(\d+))?\s+(.+)$", re.I)
RE_ENABLE = re.compile(r"^enable\s+(secret|password)(?:\s+(\d+))?\s+(.+)$", re.I)
RE_SNMP_COMM = re.compile(r"^snmp-server\s+community\s+(\S+)\s+(RO|RW)\b(?:\s+(\S+))?", re.I)
RE_SNMP_GROUP = re.compile(r"^snmp-server\s+group\s+\S+\s+v3\s+(\S+)", re.I)
RE_SNMP_USER = re.compile(r"^snmp-server\s+user\s+(\S+)\s+(\S+)\s+v3\s+(.+)$", re.I)
RE_NTP_SERVER = re.compile(r"^ntp\s+server\s+(\S+)", re.I)
RE_NTP_AUTH = re.compile(r"^ntp\s+authenticate\b", re.I)
RE_NTP_TRUST = re.compile(r"^ntp\s+trusted-key\s+(.+)$", re.I)
RE_NTP_KEY = re.compile(r"^ntp\s+authentication-key\s+(\d+)\s+\S+\s+(.+)$", re.I)
RE_RSA = re.compile(r"^crypto\s+key\s+generate\s+rsa(?:.*?modulus\s+(\d+))?", re.I)
RE_SSH_SRC = re.compile(r"^ip\s+ssh\s+source-interface\s+(\S+)", re.I)
RE_HTTP_ACL = re.compile(r"^ip\s+http\s+access-class\s+(\S+)", re.I)
RE_ARCHIVE = re.compile(r"^archive\b", re.I)
RE_CONTROL = re.compile(r"^control-plane(?:\s+(.+))?", re.I)
RE_CLASS = re.compile(r"^class-map\b", re.I)
RE_POLICY = re.compile(r"^policy-map\b", re.I)
RE_SVC_POLICY = re.compile(r"^service-policy\s+(input|output)\s+(\S+)", re.I)
RE_FLOW = re.compile(r"^(?:ip\s+flow|ip\s+flow-export|flow\s+(?:exporter|monitor|record))\b", re.I)
RE_VERIFY = re.compile(r"^ip\s+verify\s+unicast\s+source\s+reachable-via\b", re.I)
RE_SOURCE_GUARD = re.compile(r"^ip\s+verify\s+source\b|^ip\s+source-guard\b", re.I)
RE_DAI = re.compile(r"^ip\s+arp\s+inspection\s+vlan\b|^ip\s+arp\s+inspection\s+trust\b", re.I)
RE_PORTSEC = re.compile(r"^switchport\s+port-security\b", re.I)
RE_EIGRP_AUTH = re.compile(r"(?:^|\s)ip\s+authentication\s+(?:key-chain|mode\s+eigrp\b)", re.I)
RE_OSPF_AUTH = re.compile(r"^ip\s+ospf\s+message-digest-key\b|^area\s+\S+\s+authentication\s+message-digest\b", re.I)
RE_RIP_AUTH = re.compile(r"^ip\s+rip\s+authentication\s+(?:key-chain|mode)\b", re.I)
RE_BGP_AUTH = re.compile(r"^neighbor\s+\S+\s+password\b|^neighbor\s+\S+\s+ttl-security\s+hops\b", re.I)
RE_BGP_FILTER = re.compile(r"^neighbor\s+\S+\s+(?:prefix-list|filter-list|route-map)\b", re.I)
RE_BGP_MAX = re.compile(r"^neighbor\s+\S+\s+(?:maximum-prefix|max-prefix)\b", re.I)
RE_FHRP_AUTH = re.compile(r"^(?:standby|vrrp|glbp)\s+\S+\s+authentication\b", re.I)
RE_ACL_APPLY = re.compile(r"^ip\s+access-group\s+(\S+)\s+(in|out)\b", re.I)
RE_IPV6_ACL_APPLY = re.compile(r"^ipv6\s+traffic-filter\s+(\S+)\s+(in|out)\b", re.I)
RE_BANNER = re.compile(r"^banner\s+(motd|login|exec|incoming|aaa-authentication)\b", re.I)

# Broad family list for syntax recognition at top level. It is intentionally
# permissive; security-relevant extraction is performed separately.
TOP_LEVEL_FAMILIES = {
    "version","hostname","service","enable","username","aaa","security","clock","login",
    "logging","ip","ipv6","interface","line","router","route-map","ipsec","crypto","key",
    "banner","snmp-server","tacacs-server","tacacs","radius-server","ntp","archive","spanning-tree",
    "switchport","vlan","vrf","mpls","policy-map","class-map","object-group","redundancy","vpdn",
    "controller","boot-start-marker","boot-end-marker","end","exit","default","no","license","license",
    "scheduler","control-plane","flow","parameter-map","macro","event","eem","event-manager","track",
    "access-list","mac","fabric","platform","platform", "sdm", "diagnostic", "monitor", "snmp-server",
    "errdisable","multilink","call-home","archive","redundancy","redundancy","spanning-tree","udld",
    "ethernet","lacp","lacp-system","rep","vtp","dot1x","voice","service-policy","class-map",
}

SECURITY_PREFIXES = (
    "service ", "no service ", "security ", "aaa ", "enable ", "username ", "login ", "ip ssh ",
    "ip http ", "no ip http ", "ip access-list ", "ipv6 access-list ", "access-list ", "snmp-server ",
    "logging ", "ntp ", "tacacs ", "tacacs-server ", "radius-server ", "crypto key ", "banner ",
    "control-plane", "policy-map ", "class-map ", "service-policy ", "ip verify ", "ip source-guard ",
    "ip arp inspection ", "switchport port-security", "ip flow", "flow ", "neighbor ", "standby ",
    "vrrp ", "glbp ", "archive ", "configuration mode exclusive", "no vstack", "vstack ", "guestshell ",
    "cdp ", "no cdp ", "lldp ", "no lldp ", "mop ", "no mop ", "ip directed-broadcast", "no ip directed-broadcast",
    "ip source-route", "no ip source-route", "ip redirects", "no ip redirects", "ip unreachables", "no ip unreachables",
    "ip proxy-arp", "no ip proxy-arp", "no ip domain-lookup", "ip domain-lookup", "no ip finger", "ip finger",
    "no ip bootp server", "ip bootp server", "no service config", "service config", "no service pad", "service pad",
)


def _is_top_level(raw: str) -> bool:
    return not raw[:1].isspace()


def _known_line(raw: str, context: str | None) -> bool:
    line = raw.strip()
    if not line or line.startswith("!"):
        return True
    low = line.lower()
    if low.startswith(("x-", "custom-", "unknown-")):
        return False
    if not _is_top_level(raw):
        # Once inside a Cisco configuration block, nested statements are valid
        # syntax unless they use an explicitly custom prefix.
        return True
    first = low.split(None, 1)[0]
    if first in TOP_LEVEL_FAMILIES:
        return True
    if low.startswith(("ip access-list ", "ipv6 access-list ", "mac access-list ")):
        return True
    if low.startswith(SECURITY_PREFIXES):
        return True
    # Common top-level protocol/features found in real IOS captures.
    return first in {
        "router","interface","line","vrf","route-map","match","set","permit","deny","remark",
        "dialer-list","dialer","ppp","network","redistribute","passive-interface","key","object-group",
        "parameter-map","vpdn","bba-group","pvc","encapsulation","control-plane","ntp","snmp-server",
    }


def _seconds(minutes: int, seconds: int) -> int:
    return minutes * 60 + seconds


def parse_cisco(text: str, analysis_id: str, source_file: str) -> NormalizedConfig:
    controls: dict[str, Any] = {}
    evidence: dict[str, list[Evidence]] = {}
    unknown: list[Evidence] = []
    lines = text.splitlines()
    context: str | None = None
    current_interface: str | None = None
    current_line_kind: str | None = None
    current_router: str | None = None

    def obs(name: str, value: Any, idx: int, source: str):
        controls[name] = value
        evidence.setdefault(name, []).append(Evidence(line_number=idx, source=source))

    def flag(name: str, value: bool, idx: int, source: str):
        if name not in controls:
            controls[name] = value
        else:
            controls[name] = value
        evidence.setdefault(name, []).append(Evidence(line_number=idx, source=source))

    # Base fields: keep them present so missing observations become UNKNOWN in
    # the deterministic compliance layer rather than silently disappearing.
    for key in [
        "ssh_version","ssh_timeout_seconds","ssh_authentication_retries","ssh_source_interface",
        "password_min_length","hostname_configured","enable_secret_configured","enable_password_legacy_present",
        "weak_local_password_count","secure_local_secret_count","service_password_encryption",
        "login_block_configured","login_delay_seconds","login_on_failure_log","login_on_success_log",
        "aaa_new_model","aaa_login_configured","aaa_authorization_exec_configured","aaa_command_authorization_configured",
        "aaa_exec_accounting_configured","aaa_command_accounting_configured","console_exec_timeout_configured",
        "aux_disabled","vty_exec_timeout_configured","vty_telnet_enabled","vty_ssh_enabled","vty_access_class_configured",
        "vty_ipv6_access_class_configured","vty_authentication_configured","warning_banner_configured",
        "ssh_rsa_key_configured","http_server_enabled","https_server_enabled","http_access_class_configured",
        "service_password_recovery_enabled","tcp_keepalives_in","tcp_keepalives_out","service_config_enabled",
        "service_pad_enabled","tcp_small_servers_enabled","udp_small_servers_enabled","ip_finger_enabled",
        "ip_bootp_server_enabled","domain_lookup_enabled","cdp_global_disabled","lldp_global_disabled",
        "vstack_enabled","guestshell_enabled","logging_host_configured","logging_source_interface",
        "logging_buffered_configured","logging_trap_configured","logging_timestamps_configured","logging_console_enabled",
        "ntp_server_count","ntp_authentication_configured","ntp_control_messages_disabled","snmp_v1_v2_present",
        "snmp_rw_community_present","snmp_community_acl_protected","snmpv3_auth_or_priv_configured","snmpv3_priv_configured",
        "archive_configured","archive_log_configured","config_mode_exclusive","config_change_logging_configured",
        "copp_configured","cppr_configured","ip_source_route_enabled","explicit_ip_redirects_enabled",
        "explicit_ip_unreachables_enabled","explicit_proxy_arp_enabled","explicit_ip_directed_broadcast_enabled",
        "urpf_interface_count","ip_source_guard_interface_count","dai_configured","port_security_interface_count",
        "netflow_configured","private_vlan_configured","acl_count","acl_applied_interface_count",
        "ipv6_acl_count","ipv6_acl_applied_interface_count",
    ]:
        controls[key] = None

    # For counts where absence is deterministically zero in the config text,
    # initialize to 0. This is useful for explicit-feature controls.
    for key in [
        "weak_local_password_count","secure_local_secret_count","ntp_server_count","urpf_interface_count",
        "ip_source_guard_interface_count","port_security_interface_count","acl_count","acl_applied_interface_count",
        "ipv6_acl_count","ipv6_acl_applied_interface_count",
    ]:
        controls[key] = 0

    vty_blocks: list[dict[str, Any]] = []
    console_blocks: list[dict[str, Any]] = []
    aux_seen = False
    interfaces_seen: set[str] = set()
    aaa_servers: set[str] = set()
    logging_hosts: set[str] = set()
    snmp_communities: list[tuple[str,str,str|None]] = []
    snmp_v3_security: list[str] = []
    router_present: set[str] = set()
    eigrp_auth = False; ospf_auth = False; rip_auth = False; bgp_auth = False; bgp_filter = False; bgp_max = False
    fhrp_present = False; fhrp_auth = False
    archive_seen = False
    archive_log = False
    config_notify = False
    copp_policy = False; cppr_policy = False
    in_policy = False
    in_keychain = False
    in_archive = False
    in_vty_obj: dict[str, Any] | None = None
    in_console_obj: dict[str, Any] | None = None
    in_aux_obj: dict[str, Any] | None = None

    for idx, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("!"):
            if stripped.startswith("!"):
                # ! is the canonical IOS section delimiter, but nested blocks in
                # many generated configs also use it loosely. Do not erase all
                # context because the next command can be continuation text.
                if in_vty_obj is not None:
                    vty_blocks.append(in_vty_obj); in_vty_obj = None
                if in_console_obj is not None:
                    console_blocks.append(in_console_obj); in_console_obj = None
            continue
        low = stripped.lower()

        m = RE_IF.match(stripped)
        if m:
            if in_vty_obj is not None:
                vty_blocks.append(in_vty_obj); in_vty_obj=None
            current_interface = m.group("name")
            interfaces_seen.add(current_interface.lower())
            context = "interface"
            current_line_kind = None; current_router = None
            continue
        m = RE_LINE.match(stripped)
        if m:
            if in_vty_obj is not None: vty_blocks.append(in_vty_obj)
            if in_console_obj is not None: console_blocks.append(in_console_obj)
            in_vty_obj = None; in_console_obj = None
            kind = m.group("kind").lower()
            current_interface = None; current_router = None; current_line_kind = kind; context = f"line {kind}"
            if kind == "vty":
                in_vty_obj = {"transport": None, "exec_timeout": None, "access_class": False, "ipv6_access": False, "auth": False, "password": False, "line": stripped}
            elif kind in {"console","con"}:
                in_console_obj = {"exec_timeout": None, "auth": False, "line": stripped}
            elif kind == "aux":
                aux_seen = True
                in_aux_obj = {"transport_input": None, "transport_output": None, "exec_timeout": None, "exec": True, "password": False}
            continue
        m = RE_ROUTER.match(stripped)
        if m:
            if in_vty_obj is not None: vty_blocks.append(in_vty_obj); in_vty_obj=None
            current_router = (m.group("proto") or "").lower()
            router_present.add(current_router)
            context = "router"
            current_interface = None; current_line_kind = None
            continue

        if low == "archive":
            archive_seen = True; in_archive=True; context="archive"; controls["archive_configured"] = True; evidence.setdefault("archive_configured",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if low == "control-plane" or low.startswith("control-plane "):
            context="control-plane"; controls["copp_configured"] = controls.get("copp_configured") or False; continue
        if low.startswith("policy-map "):
            context="policy-map"; in_policy=True; continue
        if low.startswith("class-map "):
            context="class-map"; continue
        if low.startswith("key chain "):
            context="key-chain"; in_keychain=True; continue

        # Global identity / version
        m = RE_HOSTNAME.match(stripped)
        if m:
            obs("hostname_configured", True, idx, stripped)
            obs("hostname", m.group(1), idx, stripped)
            continue
        m = RE_VERSION.match(stripped)
        if m:
            obs("version", m.group(1).strip(), idx, stripped)
            continue

        # Services and management hardening
        if low == "service tcp-keepalives-in": obs("tcp_keepalives_in", True, idx, stripped); continue
        if low == "no service tcp-keepalives-in": obs("tcp_keepalives_in", False, idx, stripped); continue
        if low == "service tcp-keepalives-out": obs("tcp_keepalives_out", True, idx, stripped); continue
        if low == "no service tcp-keepalives-out": obs("tcp_keepalives_out", False, idx, stripped); continue
        if low == "service password-encryption": obs("service_password_encryption", True, idx, stripped); continue
        if low == "no service password-encryption": obs("service_password_encryption", False, idx, stripped); continue
        if low == "service config": obs("service_config_enabled", True, idx, stripped); continue
        if low == "no service config": obs("service_config_enabled", False, idx, stripped); continue
        if low == "service pad": obs("service_pad_enabled", True, idx, stripped); continue
        if low == "no service pad": obs("service_pad_enabled", False, idx, stripped); continue
        if low == "service tcp-small-servers": obs("tcp_small_servers_enabled", True, idx, stripped); continue
        if low == "no service tcp-small-servers": obs("tcp_small_servers_enabled", False, idx, stripped); continue
        if low == "service udp-small-servers": obs("udp_small_servers_enabled", True, idx, stripped); continue
        if low == "no service udp-small-servers": obs("udp_small_servers_enabled", False, idx, stripped); continue
        if low == "ip finger": obs("ip_finger_enabled", True, idx, stripped); continue
        if low == "no ip finger": obs("ip_finger_enabled", False, idx, stripped); continue
        if low == "ip bootp server": obs("ip_bootp_server_enabled", True, idx, stripped); continue
        if low == "no ip bootp server": obs("ip_bootp_server_enabled", False, idx, stripped); continue
        if low == "ip domain-lookup": obs("domain_lookup_enabled", True, idx, stripped); continue
        if low == "no ip domain-lookup": obs("domain_lookup_enabled", False, idx, stripped); continue
        if low == "vstack": obs("vstack_enabled", True, idx, stripped); continue
        if low == "no vstack": obs("vstack_enabled", False, idx, stripped); continue
        if low == "guestshell enable": obs("guestshell_enabled", True, idx, stripped); continue
        if low == "guestshell disable": obs("guestshell_enabled", False, idx, stripped); continue
        if low == "service password-recovery": obs("service_password_recovery_enabled", True, idx, stripped); continue
        if low == "no service password-recovery": obs("service_password_recovery_enabled", False, idx, stripped); continue
        if low == "no cdp run": obs("cdp_global_disabled", True, idx, stripped); continue
        if low == "cdp run": obs("cdp_global_disabled", False, idx, stripped); continue
        if low == "no lldp run": obs("lldp_global_disabled", True, idx, stripped); continue
        if low == "lldp run": obs("lldp_global_disabled", False, idx, stripped); continue
        if low == "ip source-route": obs("ip_source_route_enabled", True, idx, stripped); continue
        if low == "no ip source-route": obs("ip_source_route_enabled", False, idx, stripped); continue
        if low == "ip directed-broadcast": obs("explicit_ip_directed_broadcast_enabled", True, idx, stripped); continue
        if low == "no ip directed-broadcast": obs("explicit_ip_directed_broadcast_enabled", False, idx, stripped); continue
        if low == "ip redirects": obs("explicit_ip_redirects_enabled", True, idx, stripped); continue
        if low == "no ip redirects":
            if controls.get("explicit_ip_redirects_enabled") is None: controls["explicit_ip_redirects_enabled"] = False
            evidence.setdefault("explicit_ip_redirects_enabled",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if low == "ip unreachables": obs("explicit_ip_unreachables_enabled", True, idx, stripped); continue
        if low == "no ip unreachables":
            if controls.get("explicit_ip_unreachables_enabled") is None: controls["explicit_ip_unreachables_enabled"] = False
            evidence.setdefault("explicit_ip_unreachables_enabled",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if low == "ip proxy-arp": obs("explicit_proxy_arp_enabled", True, idx, stripped); continue
        if low == "no ip proxy-arp":
            if controls.get("explicit_proxy_arp_enabled") is None: controls["explicit_proxy_arp_enabled"] = False
            evidence.setdefault("explicit_proxy_arp_enabled",[]).append(Evidence(line_number=idx, source=stripped)); continue

        m = RE_NUM.match(stripped)
        if m: obs("password_min_length", int(m.group(1)), idx, stripped); continue
        m = RE_ENABLE.match(stripped)
        if m:
            typ = (m.group(1) or "").lower(); enc = m.group(2)
            if typ == "secret": obs("enable_secret_configured", True, idx, stripped)
            else: obs("enable_password_legacy_present", True, idx, stripped)
            continue
        m = RE_USERNAME.match(stripped)
        if m:
            typ = m.group(2).lower(); ptype = int(m.group(3)) if m.group(3) and m.group(3).isdigit() else None
            if typ == "password" and (ptype in {None,0,7}):
                controls["weak_local_password_count"] += 1; evidence.setdefault("weak_local_password_count",[]).append(Evidence(line_number=idx, source=stripped))
            elif typ == "secret" and ptype in {5,6,8,9}:
                if ptype in {5,6,8,9}: controls["secure_local_secret_count"] += 1; evidence.setdefault("secure_local_secret_count",[]).append(Evidence(line_number=idx, source=stripped))
                if ptype == 5:
                    controls["weak_local_password_count"] += 1; evidence.setdefault("weak_local_password_count",[]).append(Evidence(line_number=idx, source=stripped))
            continue
        m = RE_LOGIN_BLOCK.match(stripped)
        if m: obs("login_block_configured", True, idx, stripped); obs("login_block_seconds", int(m.group(1)), idx, stripped); obs("login_block_attempts", int(m.group(2)), idx, stripped); obs("login_block_window_seconds", int(m.group(3)), idx, stripped); continue
        m = RE_LOGIN_DELAY.match(stripped)
        if m: obs("login_delay_seconds", int(m.group(1)), idx, stripped); continue
        if low == "login on-failure log": obs("login_on_failure_log", True, idx, stripped); continue
        if low == "login on-success log": obs("login_on_success_log", True, idx, stripped); continue
        if low == "no login on-failure log": obs("login_on_failure_log", False, idx, stripped); continue
        if low == "no login on-success log": obs("login_on_success_log", False, idx, stripped); continue

        # AAA
        if low == "aaa new-model": obs("aaa_new_model", True, idx, stripped); continue
        m = RE_AAA_LOGIN.match(stripped)
        if m: obs("aaa_login_configured", True, idx, stripped); continue
        m = RE_AAA_AUTHZ_EXEC.match(stripped)
        if m: obs("aaa_authorization_exec_configured", True, idx, stripped); continue
        m = RE_AAA_AUTHZ_CMD.match(stripped)
        if m: obs("aaa_command_authorization_configured", True, idx, stripped); continue
        m = RE_AAA_ACCT_EXEC.match(stripped)
        if m: obs("aaa_exec_accounting_configured", True, idx, stripped); continue
        m = RE_AAA_ACCT_CMD.match(stripped)
        if m: obs("aaa_command_accounting_configured", True, idx, stripped); continue
        m = RE_TACACS_SERVER.match(stripped)
        if m: aaa_servers.add(m.group(1)); continue
        m = RE_TACACS_HOST.match(stripped)
        if m: aaa_servers.add(m.group(1)); continue
        m = RE_RADIUS_HOST.match(stripped)
        if m: aaa_servers.add(m.group(1)); continue

        # SSH
        m = RE_SSH.match(stripped)
        if m: obs("ssh_version", int(m.group(1)), idx, stripped); continue
        m = RE_SSH_TIMEOUT.match(stripped)
        if m: obs("ssh_timeout_seconds", int(m.group(1)), idx, stripped); continue
        m = RE_SSH_RETRIES.match(stripped)
        if m: obs("ssh_authentication_retries", int(m.group(1)), idx, stripped); continue
        m = RE_SSH_SRC.match(stripped)
        if m: obs("ssh_source_interface", m.group(1), idx, stripped); continue
        m = RE_RSA.match(stripped)
        if m: obs("ssh_rsa_key_configured", True, idx, stripped); obs("ssh_rsa_key_modulus", int(m.group(1)) if m.group(1) else None, idx, stripped); continue

        # HTTP/HTTPS
        if low == "ip http server": obs("http_server_enabled", True, idx, stripped); continue
        if low == "no ip http server": obs("http_server_enabled", False, idx, stripped); continue
        if low == "ip http secure-server": obs("https_server_enabled", True, idx, stripped); continue
        if low == "no ip http secure-server": obs("https_server_enabled", False, idx, stripped); continue
        m = RE_HTTP_ACL.match(stripped)
        if m: obs("http_access_class_configured", True, idx, stripped); continue

        # Lines
        m = RE_EXEC.match(stripped)
        if m:
            sec = _seconds(int(m.group(1)), int(m.group(2) or 0))
            if current_line_kind == "vty" and in_vty_obj is not None: in_vty_obj["exec_timeout"] = sec
            elif current_line_kind in {"console","con"} and in_console_obj is not None: in_console_obj["exec_timeout"] = sec
            elif current_line_kind == "aux" and in_aux_obj is not None: in_aux_obj["exec_timeout"] = sec
            continue
        m = RE_TRANSPORT_IN.match(stripped)
        if m:
            toks = {x.lower() for x in m.group(1).split()}
            if current_line_kind == "vty" and in_vty_obj is not None:
                in_vty_obj["transport"] = toks
            elif current_line_kind == "aux" and in_aux_obj is not None:
                in_aux_obj["transport_input"] = toks
            continue
        m = RE_ACCESS_CLASS.match(stripped)
        if m and current_line_kind == "vty" and in_vty_obj is not None: in_vty_obj["access_class"] = True; continue
        m = RE_IPV6_ACCESS.match(stripped)
        if m and current_line_kind == "vty" and in_vty_obj is not None: in_vty_obj["ipv6_access"] = True; continue
        m = RE_LOGIN_AUTH.match(stripped)
        if m:
            if current_line_kind == "vty" and in_vty_obj is not None: in_vty_obj["auth"] = True
            elif current_line_kind in {"console","con"} and in_console_obj is not None: in_console_obj["auth"] = True
            continue
        if low == "no exec":
            if current_line_kind == "aux" and in_aux_obj is not None: in_aux_obj["exec"] = False
            continue
        if low.startswith("password "):
            if current_line_kind == "vty" and in_vty_obj is not None: in_vty_obj["password"] = True
            elif current_line_kind == "aux" and in_aux_obj is not None: in_aux_obj["password"] = True
            continue

        # Logging
        m = RE_LOG_HOST.match(stripped)
        if m: logging_hosts.add(m.group(1)); continue
        if low == "logging source-interface " or low.startswith("logging source-interface "):
            m = RE_LOG_SOURCE.match(stripped)
            if m: obs("logging_source_interface", m.group(1), idx, stripped)
            continue
        m = RE_LOG_BUF.match(stripped)
        if m: obs("logging_buffered_configured", True, idx, stripped); continue
        m = RE_LOG_TRAP.match(stripped)
        if m: obs("logging_trap_configured", True, idx, stripped); continue
        if "logging buffered" in low: obs("logging_buffered_configured", True, idx, stripped); continue
        if low.startswith("logging trap "): obs("logging_trap_configured", True, idx, stripped); continue
        if "timestamp" in low and low.startswith("service timestamps"):
            obs("logging_timestamps_configured", True, idx, stripped); continue
        if low.startswith("logging console"):
            obs("logging_console_enabled", True, idx, stripped); continue
        if low.startswith("no logging console"):
            obs("logging_console_enabled", False, idx, stripped); continue

        # SNMP
        m = RE_SNMP_COMM.match(stripped)
        if m:
            comm, access, acl = m.group(1), m.group(2).upper(), m.group(3)
            snmp_communities.append((comm, access, acl))
            continue
        m = RE_SNMP_GROUP.match(stripped)
        if m:
            sec = m.group(1).lower(); snmp_v3_security.append(sec); continue
        if low.startswith("snmp-server group ") and " v3 " in low: snmp_v3_security.append(low.split()[-1]); continue
        if low.startswith("snmp-server user ") and " v3 " in low:
            snmp_v3_security.append("user"); continue

        # NTP
        if RE_NTP_SERVER.match(stripped): controls["ntp_server_count"] += 1; evidence.setdefault("ntp_server_count",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if RE_NTP_AUTH.match(stripped): obs("ntp_authentication_configured", True, idx, stripped); continue
        if RE_NTP_TRUST.match(stripped): obs("ntp_trusted_key_configured", True, idx, stripped); continue
        if RE_NTP_KEY.match(stripped): obs("ntp_authentication_key_configured", True, idx, stripped); continue
        if low == "ntp allow mode control" or low.startswith("ntp allow mode control "): obs("ntp_control_messages_disabled", False, idx, stripped); continue
        if low.startswith("no ntp allow mode control"): obs("ntp_control_messages_disabled", True, idx, stripped); continue

        # ACLs
        if low.startswith("ip access-list ") or re.match(r"^access-list\s+\d+", low): controls["acl_count"] += 1; evidence.setdefault("acl_count",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if RE_ACL_APPLY.match(stripped): controls["acl_applied_interface_count"] += 1; evidence.setdefault("acl_applied_interface_count",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if low.startswith("ipv6 access-list "): controls["ipv6_acl_count"] += 1; evidence.setdefault("ipv6_acl_count",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if RE_IPV6_ACL_APPLY.match(stripped): controls["ipv6_acl_applied_interface_count"] += 1; evidence.setdefault("ipv6_acl_applied_interface_count",[]).append(Evidence(line_number=idx, source=stripped)); continue

        # Interface-specific security
        if RE_VERIFY.match(stripped): controls["urpf_interface_count"] += 1; evidence.setdefault("urpf_interface_count",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if RE_SOURCE_GUARD.match(stripped): controls["ip_source_guard_interface_count"] += 1; evidence.setdefault("ip_source_guard_interface_count",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if RE_DAI.match(stripped): obs("dai_configured", True, idx, stripped); continue
        if RE_PORTSEC.match(stripped): controls["port_security_interface_count"] += 1; evidence.setdefault("port_security_interface_count",[]).append(Evidence(line_number=idx, source=stripped)); continue
        if low.startswith("no mop enabled") or low.startswith("mop enabled"):
            if low.startswith("mop enabled"): obs("mop_explicitly_enabled", True, idx, stripped)
            continue
        if low.startswith("cdp enable"):
            obs("cdp_interface_explicitly_enabled", True, idx, stripped); continue
        if low.startswith("no cdp enable"):
            obs("cdp_interface_explicitly_disabled", True, idx, stripped); continue
        if low.startswith("lldp transmit") or low.startswith("lldp receive"):
            obs("lldp_interface_explicitly_enabled", True, idx, stripped); continue
        if low.startswith("no lldp transmit") or low.startswith("no lldp receive"):
            obs("lldp_interface_explicitly_disabled", True, idx, stripped); continue

        # Routing/control-plane security
        m = RE_EIGRP_AUTH.search(stripped)
        if m and current_router == "eigrp": eigrp_auth = True; continue
        m = RE_OSPF_AUTH.search(stripped)
        if m and current_router == "ospf": ospf_auth = True; continue
        if RE_RIP_AUTH.match(stripped) and current_router in {"rip","ripng"}: rip_auth = True; continue
        if RE_BGP_AUTH.match(stripped) and current_router == "bgp": bgp_auth = True; continue
        if RE_BGP_FILTER.match(stripped) and current_router == "bgp": bgp_filter = True; continue
        if RE_BGP_MAX.match(stripped) and current_router == "bgp": bgp_max = True; continue
        if low.startswith("passive-interface") and current_router in {"eigrp","ospf","rip"}: obs(f"{current_router}_passive_interface_configured", True, idx, stripped); continue
        if low.startswith("distance ") and current_router == "bgp": continue
        if RE_FHRP_AUTH.match(stripped): fhrp_auth = True; fhrp_present = True; continue
        if re.match(r"^(standby|vrrp|glbp)\s+\S+\s+(?:ip|priority|preempt)\b", low): fhrp_present = True; continue

        # CoPP/CPPr
        m = RE_SVC_POLICY.match(stripped)
        if m and context in {"control-plane","policy-map"}:
            if context == "control-plane": copp_policy = True
            else: cppr_policy = True
            continue
        if low.startswith("control-plane service-policy") or low.startswith("control-plane cef-exception") or low.startswith("control-plane transit"):
            cppr_policy = True; continue
        if low.startswith("control-plane"):
            copp_policy = True; continue
        if in_policy and low.startswith(("class ","police ","drop","conform-action","exceed-action","shape ")):
            continue

        # NetFlow
        if RE_FLOW.match(stripped): obs("netflow_configured", True, idx, stripped); continue

        # Routing sections / general security relevant routing configuration
        if low.startswith("router bgp "):
            current_router="bgp"; router_present.add("bgp"); continue

        # Archive / config management
        if low.startswith("archive log config"):
            archive_log=True; continue
        if low.startswith("notify syslog") or low.startswith("logging enable"):
            config_notify=True; continue
        if low == "configuration mode exclusive" or low.startswith("configuration mode exclusive "):
            obs("config_mode_exclusive", True, idx, stripped); continue
        if low.startswith("path ") and in_archive: archive_seen=True; continue

        # Warning banners
        if RE_BANNER.match(stripped): obs("warning_banner_configured", True, idx, stripped); continue

        # FHRP/routing auth may appear in nested interface sections, so handle
        # them even if current_router context is not active.
        if RE_FHRP_AUTH.match(stripped): fhrp_present=True; fhrp_auth=True; continue

        if not _known_line(raw, context):
            unknown.append(Evidence(line_number=idx, source=stripped))

    if in_vty_obj is not None: vty_blocks.append(in_vty_obj)
    if in_console_obj is not None: console_blocks.append(in_console_obj)

    # Collapse VTY state across all VTY ranges. Missing VTY blocks means unknown;
    # when VTY exists, every range must satisfy the property to pass.
    if vty_blocks:
        obs("vty_exec_timeout_configured", all(x["exec_timeout"] is not None and x["exec_timeout"] > 0 for x in vty_blocks), vty_blocks[-1].get("_line", 1), "line vty aggregate")
        transports=[x["transport"] for x in vty_blocks if x.get("transport") is not None]
        if transports:
            obs("vty_telnet_enabled", any("telnet" in t for t in transports), 0 if False else 1, "; ".join(x.get("line", "line vty") for x in vty_blocks))
            obs("vty_ssh_enabled", any("ssh" in t for t in transports), 1, "; ".join(x.get("line", "line vty") for x in vty_blocks))
        else:
            controls["vty_telnet_enabled"] = None; controls["vty_ssh_enabled"] = None
        obs("vty_access_class_configured", all(x["access_class"] for x in vty_blocks if x.get("access_class") is not None or True), 1, "line vty aggregate")
        obs("vty_ipv6_access_class_configured", all(x["ipv6_access"] for x in vty_blocks), 1, "line vty aggregate")
        obs("vty_authentication_configured", all(x["auth"] for x in vty_blocks), 1, "line vty aggregate")
    else:
        controls["vty_exec_timeout_configured"] = None
        controls["vty_telnet_enabled"] = None
        controls["vty_ssh_enabled"] = None
        controls["vty_access_class_configured"] = None
        controls["vty_ipv6_access_class_configured"] = None
        controls["vty_authentication_configured"] = None

    if console_blocks:
        obs("console_exec_timeout_configured", all(x["exec_timeout"] is not None and x["exec_timeout"] > 0 for x in console_blocks), 1, "line console aggregate")
    if aux_seen:
        disabled = False
        if in_aux_obj:
            disabled = (in_aux_obj.get("exec") is False and (in_aux_obj.get("transport_input") in (None, set(), {"none"}) or "none" in (in_aux_obj.get("transport_input") or set())))
        obs("aux_disabled", disabled, 1, "line aux 0 aggregate")

    # Aggregate feature fields
    if aaa_servers:
        obs("aaa_server_count", len(aaa_servers), 1, "AAA server inventory")
    obs("logging_host_configured", bool(logging_hosts), 1, "logging host aggregate")
    if logging_hosts:
        evidence["logging_host_configured"] = [Evidence(line_number=0, source="; ".join(sorted(logging_hosts)))]
    if snmp_communities:
        obs("snmp_v1_v2_present", True, 1, "snmp-server community aggregate")
        obs("snmp_rw_community_present", any(a == "RW" for _,a,_ in snmp_communities), 1, "snmp-server community aggregate")
        obs("snmp_community_acl_protected", all(bool(acl) for _,_,acl in snmp_communities), 1, "snmp-server community ACL aggregate")
        default_comm = {c.lower() for c,_,_ in snmp_communities}
        obs("snmp_default_community_present", bool(default_comm & {"public","private"}), 1, "snmp-server community aggregate")
    else:
        controls["snmp_v1_v2_present"] = False
        controls["snmp_rw_community_present"] = False
        controls["snmp_community_acl_protected"] = None
        controls["snmp_default_community_present"] = False
    if snmp_v3_security:
        obs("snmpv3_auth_or_priv_configured", any(x in {"auth","priv","user"} for x in snmp_v3_security), 1, "SNMPv3 aggregate")
        obs("snmpv3_priv_configured", any(x == "priv" for x in snmp_v3_security), 1, "SNMPv3 aggregate")
    else:
        controls["snmpv3_auth_or_priv_configured"] = False
        controls["snmpv3_priv_configured"] = False

    if archive_seen or archive_log:
        controls["archive_configured"] = True
    controls["archive_log_configured"] = bool(archive_log)
    controls["config_change_logging_configured"] = bool(config_notify or archive_log)
    controls["copp_configured"] = bool(copp_policy)
    controls["cppr_configured"] = bool(cppr_policy)

    # Conditional routing checks: only create fields when protocol is actually configured.
    if "eigrp" in router_present: controls["eigrp_auth_configured"] = bool(eigrp_auth)
    if "ospf" in router_present: controls["ospf_auth_configured"] = bool(ospf_auth)
    if "rip" in router_present or "ripng" in router_present: controls["rip_auth_configured"] = bool(rip_auth)
    if "bgp" in router_present:
        controls["bgp_auth_configured"] = bool(bgp_auth)
        controls["bgp_filtering_configured"] = bool(bgp_filter)
        controls["bgp_max_prefix_configured"] = bool(bgp_max)
    if fhrp_present:
        controls["fhrp_auth_configured"] = bool(fhrp_auth)
    for proto in ("eigrp","ospf","rip"):
        key=f"{proto}_passive_interface_configured"
        if proto in router_present and key not in controls: controls[key]=False

    # Explicitly secure or insecure syntax: use None when config is not explicit
    # rather than pretending a platform default is universal.
    if controls["explicit_ip_redirects_enabled"] is True: controls["explicit_ip_redirects_enabled"] = True
    if controls["explicit_ip_unreachables_enabled"] is True: controls["explicit_ip_unreachables_enabled"] = True
    if controls["explicit_proxy_arp_enabled"] is True: controls["explicit_proxy_arp_enabled"] = True

    parser_lines = len([x for x in lines if x.strip() and not x.strip().startswith("!")])
    unknown_count = len(unknown)
    recognized = max(0, parser_lines - unknown_count)

    controls["interface_count"] = len(interfaces_seen)
    controls["aaa_server_count"] = controls.get("aaa_server_count", 0)
    controls["router_protocols_configured"] = sorted(router_present)

    # Human-readable inventory for dashboard/JSON consumers.
    inventory = {
        "management": {
            "aaa_servers": sorted(aaa_servers), "logging_hosts": sorted(logging_hosts),
            "vty_blocks": len(vty_blocks), "console_blocks": len(console_blocks), "aux_present": aux_seen,
        },
        "snmp": {"communities": len(snmp_communities), "v3_entries": len(snmp_v3_security)},
        "interfaces": len(interfaces_seen), "acl_ipv4_entries": controls["acl_count"],
        "acl_ipv6_entries": controls["ipv6_acl_count"], "router_protocols": sorted(router_present),
        "conditional_security_checks": sorted(k for k in controls if k.endswith("_auth_configured") or k.endswith("_filtering_configured")),
    }
    controls["security_inventory"] = inventory

    # Backward-compatible aliases used by the existing SecureMe demo/compliance
    # layer. Keep the richer vendor-specific fields above while exposing the
    # original canonical demo names as well.
    controls["telnet_enabled"] = controls.get("vty_telnet_enabled")
    controls["ssh_enabled"] = controls.get("vty_ssh_enabled")
    # Logging is considered configured when a logging host or buffered logging
    # is present. This is an observation, not a compliance decision.
    controls["logging_enabled"] = bool(
        logging_hosts or controls.get("logging_buffered_configured")
    )

    return NormalizedConfig(
        analysis_id=analysis_id,
        source_file=source_file,
        device=DeviceInfo(vendor="cisco", hostname=controls.get("hostname")),
        controls=controls,
        unknown_lines=unknown,
        evidence=evidence,
        parser_stats={
            "total_source_lines": len(lines),
            "nonempty_config_lines": parser_lines,
            "recognized_lines": recognized,
            "unknown_lines": unknown_count,
            "coverage_percent": round((recognized / parser_lines) * 100, 2) if parser_lines else 100.0,
            "ai_used_by_parser": False,
        },
    )
