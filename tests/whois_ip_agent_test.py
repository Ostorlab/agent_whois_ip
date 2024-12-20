"""Unittests for WhoisIP agent."""

from typing import List, Dict
from unittest import mock

import ipwhois
import pytest
from ostorlab.agent.message import message
from pytest_mock import plugin

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
        "asn_date": "2023-12-28",
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
            "handle": "NET-8-8-8-0-2",
            "name": "GOGL",
            "parent_handle": "NET-8-0-0-0-0",
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
        "asn_date": "2023-12-28",
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
            "handle": "NET-8-8-8-0-2",
            "name": "GOGL",
            "parent_handle": "NET-8-0-0-0-0",
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


def testAgentWhoisIP_whenRDAPIsDown_shouldRetry(
    mocker: plugin.MockerFixture,
    scan_message_ipv4: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> None:
    """Test collecting whois of an IPv4 address, when server is down should retry."""
    del agent_persist_mock
    mock_request = mocker.patch(
        "urllib.request.OpenerDirector.open", return_result=mocker.Mock(status=501)
    )

    test_agent.process(scan_message_ipv4)

    assert len(agent_mock) == 0
    assert mock_request.call_count == 2


def testWhoisIP_whenIPv4AssetReachCIDRLimit_raiseValueError(
    test_agent: whois_ip_agent.WhoisIPAgent,
    scan_message_ipv4_with_mask8: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV4 and the Limit is reached."""
    with pytest.raises(ValueError, match="Subnet mask below 16 is not supported."):
        test_agent.process(scan_message_ipv4_with_mask8)


def testWhoisIP_whenIPv4AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    test_agent: whois_ip_agent.WhoisIPAgent,
    mocker: plugin.MockerFixture,
    scan_message_ipv4_with_mask16: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV4 and the Limit is not reached."""
    mocker.patch(
        "ostorlab.agent.mixins.agent_persist_mixin.AgentPersistMixin.add_ip_network",
        return_value=False,
    )

    test_agent.process(scan_message_ipv4_with_mask16)


def testWhoisIP_whenIPv6AssetReachCIDRLimit_raiseValueError(
    test_agent: whois_ip_agent.WhoisIPAgent,
    scan_message_ipv6_with_mask64: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV6 and the Limit is reached."""
    with pytest.raises(ValueError, match="Subnet mask below 112 is not supported."):
        test_agent.process(scan_message_ipv6_with_mask64)


def testWhoisIP_whenIPv6AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    test_agent: whois_ip_agent.WhoisIPAgent,
    mocker: plugin.MockerFixture,
    scan_message_ipv6_with_mask112: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV6 and the Limit is not reached."""
    mocker.patch(
        "ostorlab.agent.mixins.agent_persist_mixin.AgentPersistMixin.add_ip_network",
        return_value=False,
    )

    test_agent.process(scan_message_ipv6_with_mask112)


def testWhoisIP_whenIPAssetHasIncorrectVersion_raiseValueError(
    test_agent: whois_ip_agent.WhoisIPAgent,
    scan_message_ipv_with_incorrect_version: message.Message,
) -> None:
    """Test the CIDR Limit in case IP has incorrect version."""
    with pytest.raises(ValueError, match="Incorrect ip version 5."):
        test_agent.process(scan_message_ipv_with_incorrect_version)


def testWhoisIP_whenIPHasNoASN_doesNotCrash(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: List[message.Message],
    mocker: plugin.MockerFixture,
    scan_message_global_ipv4_with_mask32: message.Message,
) -> None:
    """Test the CIDR Limit in case IP has no ASN."""
    mocker.patch(
        "ostorlab.agent.mixins.agent_persist_mixin.AgentPersistMixin.add_ip_network",
        return_value=True,
    )
    mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        side_effect=ipwhois.exceptions.ASNRegistryError,
    )

    test_agent.process(scan_message_global_ipv4_with_mask32)

    assert len(agent_mock) == 0


def testWhoisIP_withIPv4AndMaskButNoVersion_shouldHandleVersionCorrectly(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
) -> None:
    """Test that process() handles the case when the version is None."""
    message_data = {"host": "80.121.155.176", "mask": "29"}
    test_message = message.Message.from_data(
        selector="v3.asset.ip.v4",
        data=message_data,
    )

    with (
        mock.patch.object(test_agent, "_redis_client") as mock_redis_client,
        mock.patch.object(test_agent, "add_ip_network") as mock_add_ip_network,
        mock.patch.object(test_agent, "start", mock.MagicMock()),
        mock.patch.object(test_agent, "run", mock.MagicMock()),
        mock.patch("agent.whois_ip_agent.WhoisIPAgent.main", mock.MagicMock()),
    ):
        mock_redis_client.sismember.return_value = False

        mock_add_ip_network.return_value = None

        test_agent.process(test_message)

        mock_add_ip_network.assert_called_once()


def testWhoisIP_whenInvalidIPAddressIsProvided_raisesValueError(
    test_agent: whois_ip_agent.WhoisIPAgent,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a ValueError is raised when an invalid IP address is provided."""
    input_selector = "v3.asset.ip.v4"
    input_data = {"host": "invalid_ip", "mask": "24"}
    ip_msg = message.Message.from_data(selector=input_selector, data=input_data)

    with pytest.raises(ValueError, match="Invalid IP address: invalid_ip"):
        test_agent.process(ip_msg)


def testWhoisIp_whenASNParseErrorOccure_logWithoutCrash(
    test_agent: whois_ip_agent.WhoisIPAgent,
    scan_message_ipv4: message.Message,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: List[message.Message],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that ASNParseError is caught and logged."""
    mocker.patch(
        "ipwhois.IPWhois.lookup_rdap", side_effect=ipwhois.exceptions.ASNParseError
    )

    test_agent.process(scan_message_ipv4)

    assert len(agent_mock) == 0
    assert "ASN parse error for IP" in caplog.text
