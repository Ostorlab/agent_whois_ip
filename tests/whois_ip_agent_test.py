"""Unittests for WhoisIP agent."""
from typing import List, Dict

from ostorlab.agent.message import message

from agent import whois_ip_agent


def testAgentWhoisIP_whenIPv4Target_returnsWhoisRecord(
    scan_message_ipv4: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> None:
    """Test collecting whois of an IPv4 address."""
    test_agent.process(scan_message_ipv4)
    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.asset.ip.v4.whois"
    assert agent_mock[0].data == {
        "asn_country_code": "US",
        "asn_date": "1992-12-01",
        "asn_description": "GOOGLE, US",
        "asn_number": 15169,
        "asn_registry": "arin",
        "entities": [
            {
                "contact": {
                    "address": "1600 Amphitheatre Parkway\n"
                    "Mountain View\n"
                    "CA\n"
                    "94043\n"
                    "United States",
                    "kind": "org",
                    "name": "Google LLC",
                },
                "name": "GOGL",
            }
        ],
        "host": "8.8.8.8",
        "mask": "32",
        "network": {
            "cidr": "8.8.8.0/24",
            "handle": "NET-8-8-8-0-1",
            "name": "LVLT-GOGL-8-8-8",
            "parent_handle": "NET-8-0-0-0-1",
        },
        "version": 4,
    }


def testAgentWhoisIP_whenIPv6Target_returnsWhoisRecord(
    scan_message_ipv6: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> None:
    """Test collecting whois of an IPv6 address."""
    test_agent.process(scan_message_ipv6)
    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.asset.ip.v6.whois"
    assert agent_mock[0].data == {
        "asn_country_code": "IE",
        "asn_number": 15169,
        "asn_date": "2009-10-05",
        "asn_description": "GOOGLE, US",
        "asn_registry": "ripencc",
        "entities": [
            {
                "contact": {
                    "address": "Google Ireland Limited BARROW STREET "
                    "1ST & 2ND FLOOR 4 DUBLIN IRELAND",
                    "kind": "group",
                    "name": "Google Ireland Limited",
                },
                "name": "GOOG1-RIPE",
            },
            {
                "contact": {"kind": "individual", "name": "MNT-GOOG-PROD"},
                "name": "MNT-GOOG-PROD",
            },
            {
                "contact": {
                    "address": "Google Inc. PO BOX 369 CA 94041 "
                    "Mountain View United States",
                    "kind": "group",
                    "name": "Abuse-C Role",
                },
                "name": "AR15518-RIPE",
            },
        ],
        "host": "2a00:1450:4006:80e::200e",
        "mask": "128",
        "network": {
            "cidr": "2a00:1450:4000::/37",
            "handle": "2a00:1450:4000::/37",
            "name": "IE-GOOGLE-2a00-1450-4000-1",
            "parent_handle": "2a00:1450::/29",
        },
        "version": 6,
    }


def testAgentWhoisIP_whenDnsRecordMsgRecieved_emitsWhoisRecords(
    scan_message_dns_resolver_record: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> None:
    """Test collecting whois of IP addresses in a dns resolver record message."""
    test_agent.process(scan_message_dns_resolver_record)

    assert len(agent_mock) == len(scan_message_dns_resolver_record.data["values"])
    assert agent_mock[0].selector == "v3.asset.ip.v4.whois"


def testAgentWhoisIP_whenDnsAAAAMsgRecieved_emitsWhoisRecords(
    scan_message_dns_aaaa_record: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> None:
    """Test collecting whois of IP addresses in a dns aaaa record message."""
    test_agent.process(scan_message_dns_aaaa_record)

    assert len(agent_mock) == len(scan_message_dns_aaaa_record.data["values"])
    assert agent_mock[0].selector == "v3.asset.ip.v6.whois"


def testAgentWhoisIP_whenIPv4WithMaskTarget_returnsWhoisRecord(
    scan_message_ipv4_mask: message.Message,
    scan_message_ipv4_mask_2: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> None:
    """Test collecting whois of an IPv4 address."""
    test_agent.process(scan_message_ipv4_mask)
    assert len(agent_mock) == 2
    assert agent_mock[0].selector == "v3.asset.ip.v4.whois"
    assert agent_mock[0].data == {
        "asn_country_code": "US",
        "asn_date": "1992-12-01",
        "asn_description": "GOOGLE, US",
        "asn_number": 15169,
        "asn_registry": "arin",
        "entities": [
            {
                "contact": {
                    "address": "1600 Amphitheatre Parkway\n"
                    "Mountain View\n"
                    "CA\n"
                    "94043\n"
                    "United States",
                    "kind": "org",
                    "name": "Google LLC",
                },
                "name": "GOGL",
            }
        ],
        "host": "8.8.8.1",
        "mask": "32",
        "network": {
            "cidr": "8.8.8.0/24",
            "handle": "NET-8-8-8-0-1",
            "name": "LVLT-GOGL-8-8-8",
            "parent_handle": "NET-8-0-0-0-1",
        },
        "version": 4,
    }
    test_agent.process(scan_message_ipv4_mask_2)
    assert len(agent_mock) == 2


def testAgentWhoisIP_whenDomainScopeArgAndDnsRecordMsgInScope_emitsWhoisRecords(
    scan_message_dns_resolver_record: message.Message,
    whois_ip_agent_with_scope_arg: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> None:
    """Ensure the domain scope argument is enforced, and dns records of domains in the scope should be processed."""
    del agent_persist_mock

    whois_ip_agent_with_scope_arg.process(scan_message_dns_resolver_record)

    assert len(agent_mock) == len(scan_message_dns_resolver_record.data["values"])
    assert agent_mock[0].selector == "v3.asset.ip.v4.whois"


def testAgentWhoisIP_whenDomainScopeArgAndDnsRecordMsgNotInScope_targetShouldNotBeProcessed(
    whois_ip_agent_with_scope_arg: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> None:
    """Ensure the domain scope argument is enforced, and dns records of
    domains not in the scope should not be processed."""
    del agent_persist_mock
    selector = "v3.asset.domain_name.dns_record"
    msg_data = {
        "name": "google.co",
        "record": "resolver",
        "values": ["8.8.8.8", "8.8.8.9", "8.8.8.10"],
    }
    msg = message.Message.from_data(selector, data=msg_data)

    whois_ip_agent_with_scope_arg.process(msg)

    assert len(agent_mock) == 0
