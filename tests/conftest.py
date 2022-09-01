"""Pytest fixture for the WhoisIP agent."""
import pathlib
import random

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions

from agent import whois_ip_agent


@pytest.fixture
def scan_message_ipv4():
    """Creates a dummy message of IPv4 asset.
    """
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '8.8.8.8',
        'mask': '32',
        'version': 4
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_ipv4_mask():
    """Creates a dummy message of IPv4 asset.
    """
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '8.8.8.0',
        'version': 4,
        'mask': '30'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_ipv4_mask_2():
    """Creates a dummy message of IPv4 asset.
    """
    selector = 'v3.asset.ip.v4'
    msg_data = {
        'host': '8.8.8.0',
        'version': 4,
        'mask': '31'
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_ipv6():
    """Creates a dummy message of IPv6 asset.
    """
    selector = 'v3.asset.ip.v6'
    msg_data = {
        'host': '2a00:1450:4006:80e::200e',
        'version': 6
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_dns_resolver_record():
    """Creates a dummy message of dns_record asset.
    """
    selector = 'v3.asset.domain_name.dns_record'
    msg_data = {
        'name': 'ostorlab.co',
        'record': 'resolver',
        'values': [
            '8.8.8.8',
            '8.8.8.9',
            '8.8.8.10'
        ]
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_dns_aaaa_record():
    """Creates a dummy message of dns_record asset.
    """
    selector = 'v3.asset.domain_name.dns_record'
    msg_data = {
        'name': 'ostorlab.co',
        'record': 'aaaa',
        'values': [
            '2a05:d014:275:cb00:ec0d:12e2:df27:aa60',
            '2a03:b0c0:3:d0::d23:4001'
        ]
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def test_agent():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/whois_ip',
            bus_url='NA',
            bus_exchange_topic='NA',
            redis_url='redis://redis',
            args=[],
            healthcheck_port=random.randint(4000, 5000))
        return whois_ip_agent.WhoisIPAgent(definition, settings)

