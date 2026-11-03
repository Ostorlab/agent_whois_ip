"""Unittests for the whois of an ASN."""

from typing import Any
from unittest import mock

import pytest
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import asn_whois_data_handler, whois_ip_agent

ARIN_RECORD: dict[str, Any] = {
    "objectClassName": "autnum",
    "handle": "AS15169",
    "name": "GOOGLE",
    "port43": "whois.arin.net",
    "events": [
        {"eventAction": "last changed", "eventDate": "2012-02-24T09:44:34-05:00"},
        {"eventAction": "registration", "eventDate": "2000-03-30T00:00:00-05:00"},
    ],
    "links": [
        {
            "rel": "self",
            "href": "https://rdap.arin.net/registry/autnum/15169",
        }
    ],
    "entities": [
        {
            "roles": ["technical"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"]]],
        },
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]],
            ],
        },
    ],
}

APNIC_RECORD: dict[str, Any] = {
    "objectClassName": "autnum",
    "handle": "AS4134",
    "name": "CHINANET-BACKBONE",
    "country": "CN",
    "port43": "whois.apnic.net",
    "events": [
        {"eventAction": "registration", "eventDate": "2008-09-04T06:40:34Z"},
        {"eventAction": "last changed", "eventDate": "2021-06-15T08:05:05Z"},
    ],
    "links": [{"rel": "self", "href": "https://rdap.apnic.net/autnum/4134"}],
    "entities": [
        {
            "roles": ["abuse"],
            "vcardArray": ["vcard", [["fn", {}, "text", "IRT-CHINANET-CN"]]],
        }
    ],
}


@pytest.fixture
def scan_message_asn() -> message.Message:
    """Creates a dummy message of ASN asset."""
    return message.Message.from_data("v3.asset.asn", data={"asn": "15169"})


def testAgentWhoisIP_whenAsnTarget_emitsAsnWhoisRecord(
    scan_message_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch(
        "agent.asn_whois_data_handler.get_asn_record", return_value=ARIN_RECORD
    )

    test_agent.process(scan_message_asn)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.asset.asn.whois"
    assert agent_mock[0].data == {
        "asn": "15169",
        "name": "GOOGLE",
        "org": "Google LLC",
        "registry": "arin",
        "allocated_date": "2000-03-30",
        "updated_date": "2012-02-24",
        "rdap_url": "https://rdap.arin.net/registry/autnum/15169",
    }


def testAgentWhoisIP_whenSameAsnTwice_emitsOnce(
    scan_message_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    lookup = mocker.patch(
        "agent.asn_whois_data_handler.get_asn_record", return_value=ARIN_RECORD
    )

    test_agent.process(scan_message_asn)
    test_agent.process(scan_message_asn)

    assert len(agent_mock) == 1
    assert lookup.call_count == 1


def testAgentWhoisIP_whenAsnHasNoRdapRecord_emitsNothing(
    scan_message_asn: message.Message,
    test_agent: whois_ip_agent.WhoisIPAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("agent.asn_whois_data_handler.get_asn_record", return_value=None)

    test_agent.process(scan_message_asn)

    assert len(agent_mock) == 0


def testPrepareAsnWhoisMessageData_whenRecordHasCountry_setsCountryCode() -> None:
    data = asn_whois_data_handler.prepare_asn_whois_message_data("4134", APNIC_RECORD)

    assert data == {
        "asn": "4134",
        "name": "CHINANET-BACKBONE",
        "country_code": "CN",
        "registry": "apnic",
        "allocated_date": "2008-09-04",
        "updated_date": "2021-06-15",
        "rdap_url": "https://rdap.apnic.net/autnum/4134",
    }


def testGetAsnRecord_whenRegistryDoesNotKnowTheAsn_returnsNone(
    mocker: plugin.MockerFixture,
) -> None:
    mocker.patch("requests.get", return_value=mock.Mock(status_code=404))

    assert asn_whois_data_handler.get_asn_record("4242424242") is None


def testPrepareAsnWhoisMessageData_whenRecordComesFromRegistroBr_setsLacnicRegistry() -> (
    None
):
    record = {
        "name": "ASN28573",
        "country": "BR",
        "links": [{"rel": "self", "href": "https://rdap.registro.br/autnum/28573"}],
    }

    data = asn_whois_data_handler.prepare_asn_whois_message_data("28573", record)

    assert data["registry"] == "lacnic"
    assert data["country_code"] == "BR"
