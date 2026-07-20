"""Pytest fixture for the WhoisIP agent."""

import pathlib
import json
from typing import Dict, Any

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import definitions

from agent import whois_ip_agent


@pytest.fixture
def scan_message_ipv4() -> message.Message:
    """Creates a dummy message of IPv4 asset."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "8.8.8.8", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_ipv4_mask() -> message.Message:
    """Creates a dummy message of IPv4 asset."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "8.8.8.0", "version": 4, "mask": "30"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_ipv4_mask_2() -> message.Message:
    """Creates a dummy message of IPv4 asset."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "8.8.8.0", "version": 4, "mask": "31"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_ipv6() -> message.Message:
    """Creates a dummy message of IPv6 asset."""
    selector = "v3.asset.ip.v6"
    msg_data = {"host": "2a00:1450:4006:80e::200e", "version": 6}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_dns_resolver_record() -> message.Message:
    """Creates a dummy message of dns_record asset."""
    selector = "v3.asset.domain_name.dns_record"
    msg_data = {
        "name": "ostorlab.co",
        "record": "resolver",
        "values": ["8.8.8.8", "8.8.8.9", "8.8.8.10"],
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_dns_aaaa_record() -> message.Message:
    """Creates a dummy message of dns_record asset."""
    selector = "v3.asset.domain_name.dns_record"
    msg_data = {
        "name": "ostorlab.co",
        "record": "aaaa",
        "values": [
            "2a05:d014:275:cb00:ec0d:12e2:df27:aa60",
            "2a03:b0c0:3:d0::d23:4001",
        ],
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def test_agent() -> whois_ip_agent.WhoisIPAgent:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/whois_ip",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[],
            healthcheck_port=0,
        )
        return whois_ip_agent.WhoisIPAgent(definition, settings)


@pytest.fixture
def whois_ip_agent_with_scope_arg(
    agent_persist_mock: Dict[str | bytes, str | bytes],
) -> whois_ip_agent.WhoisIPAgent:
    """WhoisIP Agent fixture with domain scope regex argument for testing purposes."""
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/whois_ip",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[
                definitions.Arg(
                    name="scope_domain_regex",
                    type="string",
                    value=json.dumps(".*ostorlab.co").encode(),
                ),
            ],
            healthcheck_port=0,
        )
        return whois_ip_agent.WhoisIPAgent(definition, settings)


@pytest.fixture()
def scan_message_ipv4_with_mask8() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "8", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv4_with_mask16() -> message.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "16", "version": 4}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask64() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "64",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask112() -> message.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "112",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv_with_incorrect_version() -> message.Message:
    """Creates a message of type v3.asset.ip with an incorrect version."""
    selector = "v3.asset.ip"
    msg_data = {
        "host": "0.0.0.0",
        "mask": "32",
        "version": 5,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_global_ipv4_with_mask32() -> message.Message:
    """Creates a message of type v3.asset.ip with global IP address"""
    selector = "v3.asset.ip"
    msg_data = {
        "host": "41.0.0.0",
        "mask": "32",
        "version": 4,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_asn() -> message.Message:
    """Creates a dummy message of an ASN asset.

    The shared ``v3.asset.ip.asn`` message proto is added separately, so the
    message is built directly to avoid relying on a registered proto.
    """
    return message.Message(
        selector="v3.asset.ip.asn",
        data={"asn": "AS15169"},
        raw=b"",
    )


@pytest.fixture
def mock_asn_origin_lookup(mocker: Any) -> None:
    """Mocks the ipwhois ASN origin lookup to avoid live network requests."""

    def _mock_lookup(asn: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "query": asn,
            "nets": [
                {"cidr": "8.8.8.0/24", "start": 0, "end": 10},
                {"cidr": "8.8.4.0/24", "start": 11, "end": 21},
                {"cidr": "8.8.8.0/24", "start": 22, "end": 32},
                {"cidr": "2a00:1450:4000::/37", "start": 33, "end": 50},
            ],
            "raw": None,
        }

    mocker.patch("ipwhois.asn.ASNOrigin.lookup", side_effect=_mock_lookup)


@pytest.fixture
def mock_whois_lookup(mocker: Any) -> None:
    """Mocks the rdap lookup to avoid live network requests."""

    def _mock_get_whois_record(host: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        if ":" in host:
            return {
                "asn_country_code": "IE",
                "asn": "15169",
                "asn_date": "2009-10-05",
                "asn_description": "GOOGLE, US",
                "asn_registry": "ripencc",
                "objects": {
                    "GOOG1-RIPE": {
                        "contact": {
                            "address": [
                                {
                                    "value": "Google Ireland Limited BARROW STREET 1ST & 2ND FLOOR 4 DUBLIN IRELAND"
                                }
                            ],
                            "kind": "group",
                            "name": "Google Ireland Limited",
                        },
                        "handle": "GOOG1-RIPE",
                    },
                    "MNT-GOOG-PROD": {
                        "contact": {
                            "kind": "individual",
                            "name": "MNT-GOOG-PROD",
                            "address": None,
                        },
                        "handle": "MNT-GOOG-PROD",
                    },
                    "AR15518-RIPE": {
                        "contact": {
                            "address": [
                                {
                                    "value": "Google Inc. PO BOX 369 CA 94041 Mountain View United States"
                                }
                            ],
                            "kind": "group",
                            "name": "Abuse-C Role",
                        },
                        "handle": "AR15518-RIPE",
                    },
                },
                "network": {
                    "cidr": "2a00:1450:4000::/37",
                    "handle": "2a00:1450:4000::/37",
                    "name": "IE-GOOGLE-2a00-1450-4000-1",
                    "parent_handle": "2a00:1450::/29",
                },
            }
        else:
            return {
                "asn_country_code": "US",
                "asn_date": "2023-12-28",
                "asn_description": "GOOGLE, US",
                "asn": "15169",
                "asn_registry": "arin",
                "objects": {
                    "GOGL": {
                        "contact": {
                            "address": [
                                {
                                    "value": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                                }
                            ],
                            "kind": "org",
                            "name": "Google LLC",
                        },
                        "handle": "GOGL",
                    }
                },
                "network": {
                    "cidr": "8.8.8.0/24",
                    "handle": "NET-8-8-8-0-2",
                    "name": "GOGL",
                    "parent_handle": "NET-8-0-0-0-0",
                },
            }

    mocker.patch(
        "agent.whois_ip_agent._get_whois_record", side_effect=_mock_get_whois_record
    )
