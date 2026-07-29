"""Unittests for the ipwhois data handler."""

import ipaddress
import json
import urllib.error
from io import BytesIO
from typing import Any
from unittest import mock

import pytest
from pytest_mock import plugin

from agent import ipwhois_data_handler


def _ripe_response(prefixes: list[str], status: str = "ok") -> bytes:
    payload = {
        "status": status,
        "data": {"resource": "15169", "prefixes": [{"prefix": p} for p in prefixes]},
    }
    return json.dumps(payload).encode("utf-8")


def testNormalizeAsn_whenPrefixedWithAs_returnsNormalizedAsn() -> None:
    """Test that an ASN already prefixed with AS is normalized."""
    assert ipwhois_data_handler.normalize_asn("AS15169") == "AS15169"


def testNormalizeAsn_whenMissingPrefix_returnsPrefixedAsn() -> None:
    """Test that an ASN without the AS prefix gets it added."""
    assert ipwhois_data_handler.normalize_asn("15169") == "AS15169"


def testNormalizeAsn_whenLowercasePrefix_returnsUppercaseAsn() -> None:
    """Test that a lowercase AS prefix is normalized to uppercase."""
    assert ipwhois_data_handler.normalize_asn("as15169") == "AS15169"


def testNormalizeAsn_whenNotNumeric_raisesValueError() -> None:
    """Test that a non-numeric ASN raises a ValueError."""
    with pytest.raises(ValueError, match="Invalid ASN"):
        ipwhois_data_handler.normalize_asn("ASGOOGLE")


def testNormalizeAsn_whenUnicodeDigits_raisesValueError() -> None:
    """Test that ASN normalization accepts ASCII digits only."""
    with pytest.raises(ValueError, match="Invalid ASN"):
        ipwhois_data_handler.normalize_asn("AS①")


def testGetNetworksForAsn_whenLookupReturnsPrefixes_returnsDeduplicatedNetworks(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that announced prefixes are parsed and deduplicated."""
    mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        return_value=["8.8.8.0/24", "8.8.4.0/24", "8.8.8.0/24", "2a00:1450:4000::/37"],
    )

    networks = ipwhois_data_handler.get_networks_for_asn("AS15169")

    assert len(networks) == 3
    assert ipaddress.ip_network("8.8.8.0/24") in networks
    assert ipaddress.ip_network("8.8.4.0/24") in networks
    assert ipaddress.ip_network("2a00:1450:4000::/37") in networks


def testGetNetworksForAsn_supportsIpv4AndIpv6(mocker: plugin.MockerFixture) -> None:
    """Test that both IPv4 and IPv6 prefixes are supported."""
    mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        return_value=["45.237.228.0/22", "2801:80:2400::/48"],
    )

    networks = ipwhois_data_handler.get_networks_for_asn("AS268302")

    assert ipaddress.ip_network("45.237.228.0/22") in networks
    assert ipaddress.ip_network("2801:80:2400::/48") in networks
    assert {type(n) for n in networks} == {
        ipaddress.IPv4Network,
        ipaddress.IPv6Network,
    }


def testGetNetworksForAsn_whenPrefixIsInvalid_skipsEntry(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that invalid prefix values are skipped without raising."""
    mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        return_value=["not-a-network", "8.8.8.0/24"],
    )

    networks = ipwhois_data_handler.get_networks_for_asn("AS15169")

    assert len(networks) == 1
    assert networks[0] == ipaddress.ip_network("8.8.8.0/24")


def testGetNetworksForAsn_normalizesAsnBeforeLookup(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that the ASN is normalized before being passed to the lookup."""
    spy = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes", return_value=[]
    )

    ipwhois_data_handler.get_networks_for_asn("15169")

    assert spy.call_args.args[0] == "AS15169"


def testGetNetworksForAsn_whenInvalidAsn_raisesValueError(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that an invalid ASN raises a ValueError before lookup."""
    fetch_mock = mocker.patch("agent.ipwhois_data_handler._fetch_ripe_prefixes")

    with pytest.raises(ValueError, match="Invalid ASN"):
        ipwhois_data_handler.get_networks_for_asn("ASGOOGLE")

    assert fetch_mock.call_count == 0


def testFetchRipePrefixes_returnsPrefixesFromResponse(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that prefixes are extracted from a RIPE response."""
    response = BytesIO(_ripe_response(["45.237.228.0/22", "2801:80:2400::/48"]))
    response_ctx = mock.MagicMock()
    response_ctx.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response_ctx)

    prefixes = ipwhois_data_handler._fetch_ripe_prefixes("AS268302")

    assert prefixes == ["45.237.228.0/22", "2801:80:2400::/48"]


def testFetchRipePrefixes_whenStatusNotOk_raisesRipeLookupError(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a non-ok status raises a retryable RipeLookupError."""
    response = BytesIO(_ripe_response([], status="error"))
    response_ctx = mock.MagicMock()
    response_ctx.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response_ctx)

    with pytest.raises(ipwhois_data_handler.RipeLookupError):
        ipwhois_data_handler._fetch_ripe_prefixes("AS268302")


def testFetchRipePrefixes_whenDataIsNull_raisesRipeLookupError(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a null data field raises a controlled lookup error."""
    response = BytesIO(json.dumps({"status": "ok", "data": None}).encode("utf-8"))
    response_ctx = mock.MagicMock()
    response_ctx.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response_ctx)

    with pytest.raises(ipwhois_data_handler.RipeLookupError):
        ipwhois_data_handler._fetch_ripe_prefixes("AS268302")


def testFetchRipePrefixes_whenPrefixEntryIsNotAnObject_skipsEntry(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that malformed prefix entries are ignored."""
    response = BytesIO(
        json.dumps(
            {
                "status": "ok",
                "data": {"prefixes": [None, "not-an-object", {"prefix": "8.8.8.0/24"}]},
            }
        ).encode("utf-8")
    )
    response_ctx = mock.MagicMock()
    response_ctx.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response_ctx)

    assert ipwhois_data_handler._fetch_ripe_prefixes("AS15169") == ["8.8.8.0/24"]


def testFetchRipePrefixes_whenPrefixesIsNotAList_raisesRipeLookupError(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that an invalid prefixes type raises a controlled lookup error."""
    response = BytesIO(
        json.dumps({"status": "ok", "data": {"prefixes": 42}}).encode("utf-8")
    )
    response_ctx = mock.MagicMock()
    response_ctx.__enter__.return_value = response
    mocker.patch("urllib.request.urlopen", return_value=response_ctx)

    with pytest.raises(ipwhois_data_handler.RipeLookupError):
        ipwhois_data_handler._fetch_ripe_prefixes("AS15169")


def testFetchRipePrefixes_whenNetworkError_raisesRipeLookupError(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a network error raises a retryable RipeLookupError."""
    mocker.patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.URLError("connection refused"),
    )

    with pytest.raises(ipwhois_data_handler.RipeLookupError):
        ipwhois_data_handler._fetch_ripe_prefixes("AS268302")


def testFetchRipePrefixes_usesAnnouncedPrefixesResource(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that the request targets the announced-prefixes endpoint with the ASN."""
    response = BytesIO(_ripe_response(["8.8.8.0/24"]))
    response_ctx = mock.MagicMock()
    response_ctx.__enter__.return_value = response
    request_spy = mocker.patch("urllib.request.urlopen", return_value=response_ctx)

    ipwhois_data_handler._fetch_ripe_prefixes("AS15169")

    request_obj: Any = request_spy.call_args.args[0]
    assert "announced-prefixes" in request_obj.full_url
    assert "resource=AS15169" in request_obj.full_url
