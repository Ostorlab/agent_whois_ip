"""Unittests for WhoisIP agent."""

import ipaddress
from typing import Any
from unittest import mock

import ipwhois
import pytest
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import ipwhois_data_handler, whois_ip_agent


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
    agent_mock: list[message.Message],
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


def _asn_message(asn: object, description: str | None = None) -> message.Message:
    """Build an ASN message without requiring the unreleased OXO serializer."""
    data = {"asn": asn}
    if description is not None:
        data["description"] = description
    return message.Message(selector="v3.asset.asn", data=data, raw=b"")


def testAgentWhoisIP_whenAsnSelector_emitsCanonicalSingletonNetworkMessages(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Route ASN input to RIPE and emit canonical IPv4 and IPv6 ranges."""
    del agent_persist_mock
    networks = [
        ipaddress.ip_network("45.237.228.7/22", strict=False),
        ipaddress.ip_network("2001:db8:1234::42/48", strict=False),
    ]
    lookup_mock = mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn",
        return_value=networks,
    )
    emit_mock = mocker.patch.object(test_agent, "emit")
    process_ip_mock = mocker.patch.object(test_agent, "_process_ip")
    whois_mock = mocker.patch("agent.whois_ip_agent._get_whois_record")

    test_agent.process(
        _asn_message(" as0268302 ", description="found from organization keyword")
    )

    lookup_mock.assert_called_once_with("AS268302")
    assert emit_mock.call_args_list == [
        mock.call(
            "v3.asset.network",
            {"ips": [{"host": "45.237.228.0", "mask": "22", "version": 4}]},
        ),
        mock.call(
            "v3.asset.network",
            {"ips": [{"host": "2001:db8:1234::", "mask": "48", "version": 6}]},
        ),
    ]
    process_ip_mock.assert_not_called()
    whois_mock.assert_not_called()


def testAgentWhoisIP_whenSelectorOnlyContainsAsnData_doesNotExpand(
    test_agent: whois_ip_agent.WhoisIPAgent,
    mocker: plugin.MockerFixture,
) -> None:
    """Require the exact ASN selector instead of routing by data shape."""
    lookup_mock = mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn"
    )
    other_message = message.Message(
        selector="v3.asset.organization", data={"asn": "AS268302"}, raw=b""
    )

    test_agent.process(other_message)

    lookup_mock.assert_not_called()


@pytest.mark.parametrize("asn", [None, "", "AS", "AS0", "ASinvalid", 268302])
def testAgentWhoisIP_whenAsnInvalid_doesNotLookUpOrPersist(
    asn: object,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Safely reject invalid ASN assets before lookup or persistence."""
    lookup_mock = mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn"
    )
    emit_mock = mocker.patch.object(test_agent, "emit")

    test_agent.process(_asn_message(asn))

    lookup_mock.assert_not_called()
    emit_mock.assert_not_called()
    assert agent_persist_mock == {}


def testAgentWhoisIP_whenNetworksOverlap_deduplicatesOnlyExactCidr(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Emit a supernet and subnet while suppressing an exact duplicate."""
    del agent_persist_mock
    mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn",
        return_value=[
            ipaddress.ip_network("192.0.0.0/16"),
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("192.0.2.0/24"),
        ],
    )
    emit_mock = mocker.patch.object(test_agent, "emit")

    test_agent.process(_asn_message("AS268302"))

    assert [call.args[1]["ips"][0] for call in emit_mock.call_args_list] == [
        {"host": "192.0.0.0", "mask": "16", "version": 4},
        {"host": "192.0.2.0", "mask": "24", "version": 4},
    ]


def testAgentWhoisIP_whenAsnSucceeds_marksProcessedOnlyAfterEmission(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Do not mark an ASN processed until lookup and every emit succeed."""
    processed_set = whois_ip_agent.ASN_PROCESSED_SET

    def _is_processed() -> bool:
        return "AS268302" in agent_persist_mock.get(processed_set, set())

    def _lookup(
        normalized_asn: str,
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        assert normalized_asn == "AS268302"
        assert _is_processed() is False
        return [ipaddress.ip_network("45.237.228.0/22")]

    def _emit(selector: str, data: dict[str, object]) -> None:
        assert selector == "v3.asset.network"
        assert data["ips"]
        assert _is_processed() is False

    mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn",
        side_effect=_lookup,
    )
    mocker.patch.object(test_agent, "emit", side_effect=_emit)

    test_agent.process(_asn_message("AS268302"))

    assert _is_processed() is True


def testAgentWhoisIP_whenAsnLookupFails_messageRemainsRetryable(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Release transient state and retry a failed ASN lookup on redelivery."""
    network = ipaddress.ip_network("45.237.228.0/22")
    lookup_mock = mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn",
        side_effect=[
            ipwhois_data_handler.RipeLookupError("RIPE unavailable"),
            [network],
        ],
    )
    emit_mock = mocker.patch.object(test_agent, "emit")
    asn_message = _asn_message("AS268302")

    with pytest.raises(ipwhois_data_handler.RipeLookupError):
        test_agent.process(asn_message)

    assert agent_persist_mock == {}

    test_agent.process(asn_message)

    assert lookup_mock.call_count == 2
    emit_mock.assert_called_once()
    assert "AS268302" in agent_persist_mock[whois_ip_agent.ASN_PROCESSED_SET]


def testAgentWhoisIP_whenNetworkEmitFails_releasesClaimsAndRetries(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    """Rollback ASN and CIDR claims so a failed emit can be retried."""
    network = ipaddress.ip_network("45.237.228.0/22")
    lookup_mock = mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn",
        return_value=[network],
    )
    emit_mock = mocker.patch.object(
        test_agent, "emit", side_effect=[RuntimeError("bus down"), None]
    )
    asn_message = _asn_message("AS268302")

    with pytest.raises(RuntimeError, match="bus down"):
        test_agent.process(asn_message)

    assert agent_persist_mock == {}

    test_agent.process(asn_message)

    assert lookup_mock.call_count == 2
    assert emit_mock.call_count == 2
    assert "AS268302" in agent_persist_mock[whois_ip_agent.ASN_PROCESSED_SET]


def testAgentWhoisIP_whenOneNetworkIsClaimed_stillEmitsTheRemainingNetworks(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, Any],
    mocker: plugin.MockerFixture,
) -> None:
    """Emit every free network even when an earlier one is owned by another worker."""
    claimed_cidr = "45.237.228.0/22"
    free_cidr = "2801:80:2400::/48"
    agent_persist_mock[f"{whois_ip_agent.NETWORK_CLAIM_KEY_PREFIX}:{claimed_cidr}"] = {
        claimed_cidr
    }
    mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn",
        return_value=[
            ipaddress.ip_network(claimed_cidr),
            ipaddress.ip_network(free_cidr),
        ],
    )
    emit_mock = mocker.patch.object(test_agent, "emit")

    with pytest.raises(whois_ip_agent.NetworkClaimError):
        test_agent.process(_asn_message("AS268302"))

    assert emit_mock.call_count == 1
    assert emit_mock.call_args.args == (
        "v3.asset.network",
        {"ips": [{"host": "2801:80:2400::", "mask": "48", "version": 6}]},
    )
    assert whois_ip_agent.ASN_PROCESSED_SET not in agent_persist_mock
    assert free_cidr in agent_persist_mock[whois_ip_agent.NETWORK_PROCESSED_SET]


def testAgentWhoisIP_whenNetworkClaimIsConcurrent_doesNotMarkAsnProcessed(
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_persist_mock: dict[str | bytes, Any],
    mocker: plugin.MockerFixture,
) -> None:
    """Keep the ASN retryable while another worker owns a network claim."""
    cidr = "45.237.228.0/22"
    network_claim_key = f"{whois_ip_agent.NETWORK_CLAIM_KEY_PREFIX}:{cidr}"
    agent_persist_mock[network_claim_key] = {cidr}
    mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn",
        return_value=[ipaddress.ip_network(cidr)],
    )
    emit_mock = mocker.patch.object(test_agent, "emit")

    with pytest.raises(whois_ip_agent.NetworkClaimError):
        test_agent.process(_asn_message("AS268302"))

    assert emit_mock.called is False
    assert whois_ip_agent.ASN_PROCESSED_SET not in agent_persist_mock
    assert f"{whois_ip_agent.ASN_CLAIM_KEY_PREFIX}:AS268302" not in agent_persist_mock
    assert agent_persist_mock[network_claim_key] == {cidr}


def testAgentWhoisIP_whenIpWhoisContainsAsn_doesNotCallRipe(
    scan_message_ipv4: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mock_whois_lookup: None,
    mocker: plugin.MockerFixture,
) -> None:
    """Keep IP WHOIS independent from ASN-to-network expansion."""
    del agent_persist_mock, mock_whois_lookup
    lookup_mock = mocker.patch(
        "agent.ipwhois_data_handler.get_networks_for_normalized_asn"
    )

    test_agent.process(scan_message_ipv4)

    lookup_mock.assert_not_called()
    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.asset.ip.v4.whois"
