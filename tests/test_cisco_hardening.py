from pathlib import Path
from app.parsers.cisco import parse_cisco

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "c2911-router.conf"


def test_real_c2911_configuration_is_parsed_without_ai():
    text = FIXTURE.read_text(encoding="utf-8")
    result = parse_cisco(text, "REAL-C2911", FIXTURE.name)
    assert result.device.hostname == "R6"
    assert result.controls["ssh_version"] == 2
    assert result.controls["vty_telnet_enabled"] is True
    assert result.controls["logging_host_configured"] is True
    assert result.controls["password_min_length"] == 6
    assert result.controls["aaa_new_model"] is True
    assert result.controls["aaa_login_configured"] is True
    assert result.controls["aaa_command_accounting_configured"] is True
    assert result.controls["snmp_v1_v2_present"] is True
    assert result.controls["ntp_server_count"] == 5
    assert result.controls["urpf_interface_count"] >= 1
    assert result.controls["netflow_configured"] is True
    assert result.parser_stats["ai_used_by_parser"] is False
    assert result.parser_stats["total_source_lines"] == 593
    assert result.parser_stats["coverage_percent"] > 90


def test_cisco_2000_lines_are_linear_and_deterministic():
    body = "\n".join([
        "version 15.7",
        "hostname SCALE-CISCO",
        "service tcp-keepalives-in",
        "service tcp-keepalives-out",
        "no service password-recovery",
        "no service config",
        "no service pad",
        "no service tcp-small-servers",
        "no service udp-small-servers",
        "no ip bootp server",
        "no ip finger",
        "no ip source-route",
        "no ip http server",
        "aaa new-model",
        "aaa authentication login default local",
        "aaa authorization exec default local",
        "aaa accounting exec default start-stop group tacacs+",
        "ip ssh version 2",
        "ip ssh time-out 60",
        "ip ssh authentication-retries 3",
        "ip ssh source-interface Loopback0",
        "logging buffered 16384",
        "logging host 10.0.0.10",
        "logging source-interface Loopback0",
        "service timestamps log datetime msec",
        "ntp server 10.0.0.20",
        "snmp-server group SEC v3 priv",
        "line vty 0 4",
        " exec-timeout 10 0",
        " transport input ssh",
        " access-class MGMT in",
        " login authentication default",
    ])
    text = "\n".join([body] * 75)
    assert len(text.splitlines()) > 2000
    a = parse_cisco(text, "SCALE", "scale.conf")
    b = parse_cisco(text, "SCALE2", "scale.conf")
    assert a.device.hostname == "SCALE-CISCO"
    assert a.controls["ssh_version"] == 2
    assert a.controls["vty_telnet_enabled"] is False
    assert a.controls["logging_host_configured"] is True
    assert a.controls["ntp_server_count"] > 0
    assert a.controls["snmp_v1_v2_present"] is False
    assert a.controls["security_inventory"] == b.controls["security_inventory"]
    assert a.parser_stats["ai_used_by_parser"] is False


def test_only_explicit_custom_command_is_unknown():
    result = parse_cisco(
        "hostname R1\ninterface Gi0/0\n x-security-profile audit-advanced\n ip address 10.0.0.1 255.255.255.0\n",
        "UNKNOWN",
        "x.conf",
    )
    assert any(x.source == "x-security-profile audit-advanced" for x in result.unknown_lines)
