"""Pytest fixture for the WhoisIP agent."""
import pathlib
import random
import json
from typing import Dict

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions

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
            healthcheck_port=random.randint(4000, 5000),
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
                defintions.Arg(
                    name="scope_domain_regex",
                    type="string",
                    value=json.dumps(".*ostorlab.co").encode(),
                ),
            ],
            healthcheck_port=random.randint(4000, 5000),
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
