"""Unittests for the ipwhois data handler."""

import ipaddress
from typing import Any, Dict

import ipwhois.exceptions
import pytest
from pytest_mock import plugin

from agent import ipwhois_data_handler


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


def testGetNetworksForAsn_whenLookupReturnsNets_returnsDeduplicatedNetworks(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that announced networks are parsed and deduplicated."""
    lookup_record: Dict[str, Any] = {
        "query": "AS15169",
        "nets": [
            {"cidr": "8.8.8.0/24"},
            {"cidr": "8.8.4.0/24"},
            {"cidr": "8.8.8.0/24"},
            {"cidr": "2a00:1450:4000::/37"},
        ],
        "raw": None,
    }
    mocker.patch("ipwhois.asn.ASNOrigin.lookup", return_value=lookup_record)

    networks = ipwhois_data_handler.get_networks_for_asn("AS15169")

    assert len(networks) == 3
    assert ipaddress.ip_network("8.8.8.0/24") in networks
    assert ipaddress.ip_network("8.8.4.0/24") in networks
    assert ipaddress.ip_network("2a00:1450:4000::/37") in networks


def testGetNetworksForAsn_whenNetsHaveNoCidr_skipsEntries(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that net entries without a cidr are ignored."""
    lookup_record: Dict[str, Any] = {
        "query": "AS15169",
        "nets": [{"cidr": None}, {"cidr": "8.8.8.0/24"}],
        "raw": None,
    }
    mocker.patch("ipwhois.asn.ASNOrigin.lookup", return_value=lookup_record)

    networks = ipwhois_data_handler.get_networks_for_asn("15169")

    assert len(networks) == 1
    assert networks[0] == ipaddress.ip_network("8.8.8.0/24")


def testGetNetworksForAsn_whenCidrIsInvalid_skipsEntry(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that invalid cidr values are skipped without raising."""
    lookup_record: Dict[str, Any] = {
        "query": "AS15169",
        "nets": [{"cidr": "not-a-network"}, {"cidr": "8.8.8.0/24"}],
        "raw": None,
    }
    mocker.patch("ipwhois.asn.ASNOrigin.lookup", return_value=lookup_record)

    networks = ipwhois_data_handler.get_networks_for_asn("AS15169")

    assert len(networks) == 1
    assert networks[0] == ipaddress.ip_network("8.8.8.0/24")


def testGetNetworksForAsn_whenCidrHasMultipleRanges_parsesAll(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a comma-separated cidr value is split into separate networks."""
    lookup_record: Dict[str, Any] = {
        "query": "AS15169",
        "nets": [{"cidr": "8.8.8.0/24, 8.8.4.0/24"}],
        "raw": None,
    }
    mocker.patch("ipwhois.asn.ASNOrigin.lookup", return_value=lookup_record)

    networks = ipwhois_data_handler.get_networks_for_asn("AS15169")

    assert len(networks) == 2
    assert ipaddress.ip_network("8.8.8.0/24") in networks
    assert ipaddress.ip_network("8.8.4.0/24") in networks


def testGetNetworksForAsn_whenLookupFails_raisesAsnOriginLookupError(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that lookup failures propagate as ASN origin lookup errors."""
    mocker.patch(
        "ipwhois.asn.ASNOrigin.lookup",
        side_effect=ipwhois.exceptions.ASNOriginLookupError,
    )

    with pytest.raises(ipwhois.exceptions.ASNOriginLookupError):
        ipwhois_data_handler.get_networks_for_asn("AS15169")


def testGetNetworksForAsn_normalizesAsnBeforeLookup(
    mocker: plugin.MockerFixture,
) -> None:
    """Test that the ASN is normalized before being passed to the lookup."""
    spy = mocker.patch(
        "ipwhois.asn.ASNOrigin.lookup",
        return_value={"query": "AS15169", "nets": [], "raw": None},
    )

    ipwhois_data_handler.get_networks_for_asn("15169")

    assert spy.call_args.kwargs.get("asn") == "AS15169"
