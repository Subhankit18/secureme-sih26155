from app.parsers.cisco import parse_cisco
from app.parsers.fortinet import parse_fortinet


def _repeat_cisco_body() -> str:
    return "\n".join([
        "version 15.2",
        "hostname BIG-CISCO",
        "interface GigabitEthernet0/0",
        " description uplink",
        " ip address 10.0.0.1 255.255.255.0",
        " no shutdown",
        "interface GigabitEthernet0/1",
        " description lan",
        " ip address 10.0.1.1 255.255.255.0",
        " no shutdown",
        "line vty 0 4",
        " transport input ssh",
        " login local",
        "ip ssh version 2",
        "logging host 10.10.10.10",
        "security password min-length 14",
    ])


def _repeat_fortinet_body() -> str:
    return "\n".join([
        "config system global",
        '    set hostname "BIG-FGT"',
        "    set admin-ssh enable",
        "    set admin-telnet disable",
        "end",
        "config system interface",
        '    edit "port1"',
        '        set ip 10.0.0.1/24',
        '        set allowaccess ping https ssh',
        "    next",
        "end",
        "config firewall policy",
        "    edit 1",
        '        set name "web"',
        "        set action accept",
        '        set service "HTTP" "HTTPS"',
        "    next",
        "end",
        "config system admin",
        "    set password-min-length 14",
        "end",
        "config log",
        "    set status enable",
        "end",
    ])


def test_cisco_1000_plus_lines_no_ai_and_correct_controls():
    body = _repeat_cisco_body()
    text = "\n".join([body] * 70)
    assert len(text.splitlines()) > 1000
    result = parse_cisco(text, "SCALE-CISCO", "large.conf")
    assert result.device.hostname == "BIG-CISCO"
    assert result.controls["ssh_version"] == 2
    assert result.controls["telnet_enabled"] is False
    assert result.controls["logging_enabled"] is True
    assert result.controls["password_min_length"] == 14
    assert result.unknown_lines == []


def test_fortinet_1000_plus_lines_no_ai_and_correct_controls():
    body = _repeat_fortinet_body()
    text = "\n".join([body] * 60)
    assert len(text.splitlines()) > 1000
    result = parse_fortinet(text, "SCALE-FORTI", "large.conf")
    assert result.device.hostname == "BIG-FGT"
    assert result.controls["ssh_enabled"] is True
    assert result.controls["telnet_enabled"] is False
    assert result.controls["password_min_length"] == 14
    assert result.controls["logging_enabled"] is True
    assert result.unknown_lines == []


def test_cisco_unknown_command_is_preserved_with_line_number():
    result = parse_cisco(
        "hostname R1\ninterface Gi0/0\n x-security-profile audit-advanced\n",
        "UNKNOWN-CISCO",
        "x.conf",
    )
    assert len(result.unknown_lines) == 1
    assert result.unknown_lines[0].line_number == 3
    assert result.unknown_lines[0].source == "x-security-profile audit-advanced"


def test_fortinet_unknown_set_is_preserved():
    result = parse_fortinet(
        'config system global\n    set some-future-feature enable\nend\n',
        "UNKNOWN-FORTI",
        "x.conf",
    )
    assert len(result.unknown_lines) == 1
    assert result.unknown_lines[0].source == "set some-future-feature enable"
