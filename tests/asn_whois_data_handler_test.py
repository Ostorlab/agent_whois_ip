"""Unittests for the whois of an ASN."""

from typing import Any
from unittest import mock

from pytest_mock import plugin

from agent import asn_whois_data_handler


def testPrepareAsnWhoisMessageData_whenRecordHasCountry_setsCountryCode(
    apnic_rdap_record: dict[str, Any],
) -> None:
    data = asn_whois_data_handler.prepare_asn_whois_message_data(
        "4134", apnic_rdap_record
    )

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


def testPrepareAsnWhoisMessageData_whenRecordHasNullLists_skipsThem() -> None:
    record = {
        "name": "EXAMPLE",
        "events": None,
        "links": None,
        "entities": [{"roles": None}, {"roles": ["registrant"], "vcardArray": None}],
    }

    data = asn_whois_data_handler.prepare_asn_whois_message_data("64500", record)

    assert data == {"asn": "64500", "name": "EXAMPLE"}
