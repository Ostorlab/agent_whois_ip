"""Tests for ASN normalization and RIPE announced-prefix handling."""

import http.client
import io
import ipaddress
import json
from unittest import mock

import pytest
from pytest_mock import plugin

from agent import ipwhois_data_handler


def _json_response(payload: object) -> io.BytesIO:
    """Build a context-manager response containing a JSON payload."""
    return io.BytesIO(json.dumps(payload).encode("utf-8"))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AS268302", "AS268302"),
        ("as268302", "AS268302"),
        ("268302", "AS268302"),
        ("  AS268302  ", "AS268302"),
        ("AS00268302", "AS268302"),
        ("AS4294967295", "AS4294967295"),
    ],
)
def testNormalizeAsn_whenValueIsValid_returnsCanonicalAsn(
    value: object, expected: str
) -> None:
    """Canonicalize supported ASN spellings to one deduplication identity."""
    assert ipwhois_data_handler.normalize_asn(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "AS", "AS0", "AS-1", "AS1.5", "AS 1", "AS①", "AS4294967296"],
)
def testNormalizeAsn_whenValueIsMalformed_raisesValueError(value: object) -> None:
    """Reject malformed and out-of-range ASN values."""
    with pytest.raises(ValueError, match="Invalid ASN"):
        ipwhois_data_handler.normalize_asn(value)


@pytest.mark.parametrize("value", [None, 268302])
def testNormalizeAsn_whenValueIsNotAString_raisesTypeError(value: object) -> None:
    """Reject non-string ASN values."""
    with pytest.raises(TypeError, match="Invalid ASN"):
        ipwhois_data_handler.normalize_asn(value)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"status": "error", "data": {"prefixes": []}},
        {"status": "ok", "data": None},
        {"status": "ok", "data": {}},
        {"status": "ok", "data": {"prefixes": {}}},
    ],
)
def testGetNetworksForAsn_whenPayloadMalformed_raisesAfterRetries(
    payload: object, mocker: plugin.MockerFixture
) -> None:
    """Treat malformed RIPE envelopes as retryable lookup failures."""
    responses = [
        _json_response(payload)
        for _ in range(ipwhois_data_handler.RIPE_LOOKUP_ATTEMPTS)
    ]
    open_mock = mocker.patch("urllib.request.urlopen", side_effect=responses)

    with pytest.raises(ipwhois_data_handler.RipeLookupError):
        ipwhois_data_handler.get_networks_for_normalized_asn("AS268302")

    assert open_mock.call_count == ipwhois_data_handler.RIPE_LOOKUP_ATTEMPTS


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("read timed out"),
        OSError("socket failed"),
        http.client.IncompleteRead(b"partial", 10),
    ],
)
def testGetNetworksForAsn_whenTransportOrReadFails_convertsAndRetries(
    error: BaseException,
    mocker: plugin.MockerFixture,
) -> None:
    """Convert supported transport/read failures and retry without waiting."""
    open_mock = mocker.patch(
        "urllib.request.urlopen",
        side_effect=[error for _ in range(ipwhois_data_handler.RIPE_LOOKUP_ATTEMPTS)],
    )

    with pytest.raises(ipwhois_data_handler.RipeLookupError) as exc_info:
        ipwhois_data_handler.get_networks_for_normalized_asn("AS268302")

    assert open_mock.call_count == ipwhois_data_handler.RIPE_LOOKUP_ATTEMPTS
    assert isinstance(exc_info.value.__cause__, type(error))


def testGetNetworksForAsn_whenFirstResponseFails_retriesAndReturnsPrefixes(
    mocker: plugin.MockerFixture,
) -> None:
    """Retry a failed RIPE response and return the next valid response."""
    invalid_response = {"status": "error", "data": {"prefixes": []}}
    valid_response = {
        "status": "ok",
        "data": {
            "prefixes": [
                {"prefix": "45.237.228.0/22", "timelines": []},
                {"prefix": "2801:80:2400::/48"},
                {"prefix": 42},
                None,
                {},
            ]
        },
    }
    open_mock = mocker.patch(
        "urllib.request.urlopen",
        side_effect=[
            _json_response(invalid_response),
            _json_response(valid_response),
        ],
    )

    networks = ipwhois_data_handler.get_networks_for_normalized_asn("AS268302")

    assert networks == [
        ipaddress.ip_network("45.237.228.0/22"),
        ipaddress.ip_network("2801:80:2400::/48"),
    ]
    assert open_mock.call_count == 2
    request = open_mock.call_args.args[0]
    assert request.full_url.endswith("?resource=AS268302")
    assert open_mock.call_args.kwargs["timeout"] == (
        ipwhois_data_handler.RIPE_LOOKUP_TIMEOUT_SECONDS
    )


def testGetNetworksForAsn_normalizesAndExactlyDeduplicatesMixedPrefixes(
    mocker: plugin.MockerFixture,
) -> None:
    """Canonicalize both IP families while preserving overlapping prefixes."""
    fetch_mock = mocker.patch(
        "agent.ipwhois_data_handler._fetch_ripe_prefixes",
        return_value=[
            "192.0.2.7/24",
            "192.0.2.0/24",
            "192.0.0.0/16",
            " 2001:db8:1::42/48 ",
            "2001:db8:1::/48",
            "not-a-network",
            42,
            None,
        ],
    )

    networks = ipwhois_data_handler.get_networks_for_normalized_asn("AS268302")

    assert networks == [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("192.0.0.0/16"),
        ipaddress.ip_network("2001:db8:1::/48"),
    ]
    assert fetch_mock.call_count == 1
    assert fetch_mock.call_args.args == ("AS268302",)


def testGetNetworksForAsn_buildsPublicRequestWithoutAuthentication(
    mocker: plugin.MockerFixture,
) -> None:
    """Use the public announced-prefixes endpoint without authorization."""
    response = {"status": "ok", "data": {"prefixes": []}}
    open_mock = mocker.patch(
        "urllib.request.urlopen", return_value=_json_response(response)
    )

    assert ipwhois_data_handler.get_networks_for_normalized_asn("AS15169") == []

    request: mock.MagicMock = open_mock.call_args.args[0]
    assert "announced-prefixes" in request.full_url
    assert request.full_url.endswith("?resource=AS15169")
    assert request.get_header("Authorization") is None
