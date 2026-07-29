"""Unittests for WhoisIP agent."""

from typing import Any
from unittest import mock

import ipwhois
import pytest
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import ipwhois_data_handler
from agent import whois_ip_agent


def _emitted_network_cidr(call: dict[str, Any]) -> str:
    """Return the CIDR represented by one emitted network message."""
    network_ip = call["data"]["ips"][0]
    return f"{network_ip['host']}/{network_ip['mask']}"


def testAgentWhoisIP_whenIPv4Target_returnsWhoisRecord(
    scan_message_ipv4: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_whois_lookup: None,
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_whois_lookup: None,
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_whois_lookup: None,
) -> None:
    """Test collecting whois of IP addresses in a dns resolver record message."""
    test_agent.process(scan_message_dns_resolver_record)

    assert len(agent_mock) == len(scan_message_dns_resolver_record.data["values"])
    assert agent_mock[0].selector == "v3.asset.ip.v4.whois"


def testAgentWhoisIP_whenDnsAAAAMsgRecieved_emitsWhoisRecords(
    scan_message_dns_aaaa_record: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_whois_lookup: None,
) -> None:
    """Test collecting whois of IP addresses in a dns aaaa record message."""
    test_agent.process(scan_message_dns_aaaa_record)

    assert len(agent_mock) == len(scan_message_dns_aaaa_record.data["values"])
    assert agent_mock[0].selector == "v3.asset.ip.v6.whois"


def testAgentWhoisIP_whenDnsRecordWhoisHasAsn_emitsAnnouncedNetworks(
    scan_message_dns_resolver_record: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that DNS-derived IP WHOIS ASNs are expanded through RIPE."""
    del agent_persist_mock
    whois_lookup = mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        return_value={"asn": "15169", "network": {}, "objects": {}},
    )
    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        return_value=["8.8.8.0/24", "2a00:1450:4000::/37"],
    )

    test_agent.process(scan_message_dns_resolver_record)

    assert whois_lookup.call_count == 3
    assert fetch_mock.call_count == 1
    cidrs = sorted(
        _emitted_network_cidr(call)
        for call in emit_calls
        if call["selector"] == "v3.asset.network"
    )
    assert cidrs == ["2a00:1450:4000::/37", "8.8.8.0/24"]


def testAgentWhoisIP_whenDnsRecordContainsProcessedIp_processesRemainingIps(
    scan_message_dns_resolver_record: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that one processed DNS address does not skip the remaining addresses."""
    del agent_persist_mock
    mocker.patch.object(test_agent, "set_add", side_effect=[False, True, True])
    whois_lookup = mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        return_value={"network": {}, "objects": {}},
    )

    test_agent.process(scan_message_dns_resolver_record)

    assert whois_lookup.call_count == 2
    assert len(agent_mock) == 2


def testAgentWhoisIP_whenDnsAsnExpansionFails_processesRemainingIps(
    scan_message_dns_resolver_record: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that one ASN expansion failure does not stop DNS address processing."""
    del agent_persist_mock
    mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        return_value={"asn": "15169", "network": {}, "objects": {}},
    )
    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        side_effect=[RuntimeError("RIPE unavailable"), [], []],
    )

    test_agent.process(scan_message_dns_resolver_record)

    assert fetch_mock.call_count == 2
    assert len(agent_mock) == 3
    assert "ASN expansion failed for ASN 15169" in caplog.text


def testAgentWhoisIP_whenDnsRecordIpHasAsnParseError_processesRemainingIps(
    scan_message_dns_resolver_record: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that ASNParseError on one DNS IP does not skip remaining IPs."""
    del agent_persist_mock
    good_record: dict[str, object] = {"network": {}, "objects": {}}
    mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        side_effect=[
            ipwhois.exceptions.ASNParseError("bad asn"),
            good_record,
            good_record,
        ],
    )

    test_agent.process(scan_message_dns_resolver_record)

    assert len(agent_mock) == 2
    assert "ASN parse error for IP" in caplog.text


def testAgentWhoisIP_whenDnsRecordIpHitsRateLimit_processesRemainingIps(
    scan_message_dns_resolver_record: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that HTTPRateLimitError on one DNS IP does not skip remaining IPs."""
    del agent_persist_mock
    good_record: dict[str, object] = {"network": {}, "objects": {}}
    mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        side_effect=[
            ipwhois.exceptions.HTTPRateLimitError("slow down"),
            good_record,
            good_record,
        ],
    )

    test_agent.process(scan_message_dns_resolver_record)

    assert len(agent_mock) == 2
    assert "Rate limit error for IP" in caplog.text


def testAgentWhoisIP_whenIPv4WithMaskTarget_returnsWhoisRecord(
    scan_message_ipv4_mask: message.Message,
    scan_message_ipv4_mask_2: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_whois_lookup: None,
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_whois_lookup: None,
) -> None:
    """Ensure the domain scope argument is enforced, and dns records of domains in the scope should be processed."""
    del agent_persist_mock

    whois_ip_agent_with_scope_arg.process(scan_message_dns_resolver_record)

    assert len(agent_mock) == len(scan_message_dns_resolver_record.data["values"])
    assert agent_mock[0].selector == "v3.asset.ip.v4.whois"


def testAgentWhoisIP_whenDomainScopeArgAndDnsRecordMsgNotInScope_targetShouldNotBeProcessed(
    whois_ip_agent_with_scope_arg: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_ipv4_with_mask8: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV4 and the Limit is reached."""
    with pytest.raises(ValueError, match="Subnet mask below 16 is not supported."):
        test_agent.process(scan_message_ipv4_with_mask8)


def testWhoisIP_whenIPv4AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_persist_mock: dict[str | bytes, str | bytes],
    scan_message_ipv6_with_mask64: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV6 and the Limit is reached."""
    with pytest.raises(ValueError, match="Subnet mask below 112 is not supported."):
        test_agent.process(scan_message_ipv6_with_mask64)


def testWhoisIP_whenIPv6AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
    agent_mock: list[message.Message],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that ASNParseError is caught and logged."""
    mocker.patch(
        "ipwhois.IPWhois.lookup_rdap", side_effect=ipwhois.exceptions.ASNParseError
    )

    test_agent.process(scan_message_ipv4)

    assert len(agent_mock) == 0
    assert "ASN parse error for IP" in caplog.text


def testAgentWhoisIP_whenIpWhoisHasAsn_emitsAnnouncedNetworks(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_ripe_prefixes: None,
) -> None:
    """Test that an IP WHOIS ASN emits the announced IPv4 and IPv6 ranges."""
    del agent_persist_mock
    test_agent.process(scan_message_ipv4_with_asn)

    network_messages = [c for c in emit_calls if c["selector"] == "v3.asset.network"]
    assert len(network_messages) == 3
    cidrs = sorted(_emitted_network_cidr(c) for c in network_messages)
    assert cidrs == ["2a00:1450:4000::/37", "8.8.4.0/24", "8.8.8.0/24"]
    assert all(len(c["data"]["ips"]) == 1 for c in network_messages)
    assert sum(c["selector"] == "v3.asset.ip.v4.whois" for c in emit_calls) == 1
    assert not any(
        c["selector"] in ("v3.asset.ip.v4", "v3.asset.ip.v6") for c in emit_calls
    )


def testAgentWhoisIP_whenIpWhoisHasAsn_deduplicatesNetworkRanges(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_ripe_prefixes: None,
) -> None:
    """Test that duplicate network ranges announced by an IP WHOIS ASN emit once."""
    del agent_persist_mock
    test_agent.process(scan_message_ipv4_with_asn)

    cidrs = [
        _emitted_network_cidr(c)
        for c in emit_calls
        if c["selector"] == "v3.asset.network"
    ]
    assert cidrs.count("8.8.8.0/24") == 1


def testAgentWhoisIP_whenIpAsnProcessedBefore_doesNotReprocess(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that an ASN already processed is not looked up again."""
    del emit_calls
    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes", return_value=[]
    )

    second_ip = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "8.8.4.4", "version": 4}
    )

    test_agent.process(scan_message_ipv4_with_asn)
    test_agent.process(second_ip)

    assert fetch_mock.call_count == 1


def testAgentWhoisIP_whenIpAsnProcessedConcurrently_claimPreventsDuplicateLookup(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that an in-flight ASN claim prevents a duplicate lookup."""
    del emit_calls, agent_persist_mock
    first_lookup_started = False
    second_ip = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "8.8.4.4", "version": 4}
    )

    def _fetch(resource: str) -> list[str]:
        nonlocal first_lookup_started
        assert resource == "AS15169"
        if first_lookup_started is False:
            first_lookup_started = True
            test_agent.process(second_ip)
        return []

    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes", side_effect=_fetch
    )

    test_agent.process(scan_message_ipv4_with_asn)

    assert fetch_mock.call_count == 1


def testAgentWhoisIP_whenIpAsnLookupFails_remainsRetryable(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that a failed ASN lookup is not marked processed and can be retried."""
    del agent_persist_mock

    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        side_effect=ipwhois_data_handler.RipeLookupError,
    )

    second_ip = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "8.8.4.4", "version": 4}
    )

    test_agent.process(scan_message_ipv4_with_asn)
    test_agent.process(second_ip)

    assert fetch_mock.call_count == 2
    assert sum(c["selector"].endswith(".whois") for c in emit_calls) == 2
    assert "some data not found" in caplog.text


def testAgentWhoisIP_whenUnexpectedErrorAndClaimReleaseFails_logsBothFailures(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that ASN and claim-release failures are logged without stopping WHOIS."""
    del agent_persist_mock

    original_error = RuntimeError("boom")

    def _raise_unexpected(resource: str) -> list[str]:
        del resource
        raise original_error

    mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        side_effect=_raise_unexpected,
    )
    mocker.patch.object(
        whois_ip_agent.WhoisIPAgent,
        "delete",
        side_effect=RuntimeError("redis down"),
    )

    test_agent.process(scan_message_ipv4_with_asn)

    assert "unexpected error processing ASN" in caplog.text
    assert "failed to release ASN claim" in caplog.text
    assert "ASN expansion failed for ASN 15169" in caplog.text
    assert len(emit_calls) == 1
    assert emit_calls[0]["selector"] == "v3.asset.ip.v4.whois"


def testAgentWhoisIP_whenUnexpectedError_releasesClaimAndContinues(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that an unexpected ASN error releases its claim and preserves WHOIS."""
    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        side_effect=RuntimeError("unexpected"),
    )
    delete_mock = mocker.patch.object(whois_ip_agent.WhoisIPAgent, "delete")

    test_agent.process(scan_message_ipv4_with_asn)

    assert fetch_mock.call_count == 1
    assert delete_mock.call_count == 1
    assert len(emit_calls) == 1
    assert emit_calls[0]["selector"] == "v3.asset.ip.v4.whois"


def testAgentWhoisIP_whenNetworkEmitFails_logsAndReleasesAsnClaim(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_ripe_prefixes: None,
    mocker: plugin.MockerFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test that an emit failure is logged and leaves the ASN retryable."""

    def _raise_on_emit(
        selector: str,
        data: dict[str, Any],
        message_id: str | None = None,
        message_priority: int | None = None,
    ) -> None:
        if selector == "v3.asset.network":
            raise RuntimeError("bus down")

    mocker.patch.object(test_agent, "emit", side_effect=_raise_on_emit)

    test_agent.process(scan_message_ipv4_with_asn)

    assert "failed to emit network" in caplog.text
    assert "unexpected error processing ASN" in caplog.text
    assert "ASN expansion failed for ASN 15169" in caplog.text
    assert "agent_whois_ip_asn_asset:AS15169" not in agent_persist_mock
    assert "agent_whois_ip_network_asset:8.8.8.0/24" not in agent_persist_mock


def testAgentWhoisIP_whenIpAsnProcessed_doesNotEnumerateAddresses(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_ripe_prefixes: None,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that ASN processing never enumerates individual addresses."""
    del agent_persist_mock
    whois_lookup = mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        return_value={"asn": "15169", "network": {}, "objects": {}},
    )

    test_agent.process(scan_message_ipv4_with_asn)

    assert whois_lookup.call_count == 1
    assert sum(c["selector"] == "v3.asset.network" for c in emit_calls) == 3


def testAgentWhoisIP_whenWhoisOutputReceived_doesNotTriggerExpansion(
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that the agent does not consume its own WHOIS output."""
    del agent_persist_mock
    fetch_mock = mocker.patch("agent.ipwhois_data_handler._fetch_ripe_prefixes")
    whois_message = message.Message(
        selector="v3.asset.ip.v4.whois",
        data={"asn_number": 15169},
        raw=b"",
    )

    test_agent.process(whois_message)

    assert fetch_mock.call_count == 0
    assert len(emit_calls) == 0


def testAgentWhoisIP_whenIpWhoisHasNoAsn_doesNotExpandNetworks(
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that an IP WHOIS result without an ASN emits no networks."""
    del agent_persist_mock
    mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        return_value={"network": {}, "objects": {}},
    )
    fetch_mock = mocker.patch("agent.ipwhois_data_handler._fetch_ripe_prefixes")
    ip_message = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "8.8.8.8", "version": 4}
    )

    test_agent.process(ip_message)

    assert fetch_mock.call_count == 0
    assert sum(c["selector"].endswith(".whois") for c in emit_calls) == 1
    assert not any(c["selector"] == "v3.asset.network" for c in emit_calls)


def testAgentWhoisIP_whenIpResultsShareAsn_deduplicatesLookup(
    scan_message_ipv4_with_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that two IP results with one ASN trigger one lookup."""
    del emit_calls
    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes", return_value=[]
    )
    second_ip = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "8.8.4.4", "version": 4}
    )

    test_agent.process(scan_message_ipv4_with_asn)
    test_agent.process(second_ip)

    assert fetch_mock.call_count == 1


def testAgentWhoisIP_whenOverlappingPrefixesAnnounced_emitsBothRanges(
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that overlapping prefixes (supernet and contained subnet) are both emitted."""
    del agent_persist_mock
    mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        return_value=["8.8.0.0/16", "8.8.8.0/24"],
    )
    mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        return_value={"asn": "15169", "network": {}, "objects": {}},
    )
    ip_message = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "8.8.8.8", "version": 4}
    )

    test_agent.process(ip_message)

    cidrs = sorted(
        _emitted_network_cidr(c)
        for c in emit_calls
        if c["selector"] == "v3.asset.network"
    )
    assert cidrs == ["8.8.0.0/16", "8.8.8.0/24"]


def testAgentWhoisIP_whenDuplicateCidrAcrossAsns_emittedOnce(
    test_agent: whois_ip_agent.WhoisIPAgent,
    emit_calls: list[dict[str, Any]],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a CIDR announced by two ASNs is emitted only once."""
    del agent_persist_mock
    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        return_value=["8.8.8.0/24"],
    )
    mocker.patch(
        "agent.whois_ip_agent._get_whois_record",
        side_effect=[
            {"asn": "15169", "network": {}, "objects": {}},
            {"asn": "15170", "network": {}, "objects": {}},
        ],
    )
    first_ip = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "8.8.8.8", "version": 4}
    )
    second_ip = message.Message.from_data(
        "v3.asset.ip.v4", data={"host": "8.8.4.4", "version": 4}
    )

    test_agent.process(first_ip)
    test_agent.process(second_ip)

    assert fetch_mock.call_count == 2
    cidrs = [
        _emitted_network_cidr(c)
        for c in emit_calls
        if c["selector"] == "v3.asset.network"
    ]
    assert cidrs == ["8.8.8.0/24"]
