"""Helper module for preparing WHOIS IP messages and ASN network ranges."""

import collections.abc
import http.client
import ipaddress
import json
import logging
import urllib.request
from typing import Any

import tenacity
from ostorlab.agent.message import message as m

logger = logging.getLogger(__name__)

RIPE_ANNOUNCED_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_LOOKUP_TIMEOUT_SECONDS = 15
RIPE_LOOKUP_ATTEMPTS = 2
RIPE_LOOKUP_RETRY_WAIT_SECONDS = 3
RIPE_USER_AGENT = "agent_whois_ip"
MAX_ASN_NUMBER = 4_294_967_295


class Error(Exception):
    """Base error for the ipwhois data handler module."""


class RipeLookupError(Error):
    """Raised when the RIPE announced-prefixes lookup fails."""


def prepare_whois_message_data(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, record: dict[str, Any]
) -> dict[str, Any]:
    """Prepares data of the whois IP message.

    Args:
        ip: IP address target of the whois data.
        record: Whois data records.

    Returns:
        Dict whois message.
    """

    whois_message: dict[str, Any] = {
        "host": str(ip),
        "mask": str(ip.max_prefixlen),
        "version": ip.version,
        "network": {
            "cidr": record.get("network", {}).get("cidr"),
            "name": record.get("network", {}).get("name"),
            "handle": record.get("network", {}).get("handle"),
            "parent_handle": record.get("network", {}).get("parent_handle"),
        },
        "entities": [
            {
                "name": e.get("handle"),
                "contact": {
                    "name": e.get("contact", {}).get("name"),
                    "kind": e.get("contact", {}).get("kind"),
                    "address": _get_entity_address(e),
                },
            }
            for e in record.get("objects", {}).values()
        ],
    }

    if record.get("asn_registry") is not None:
        whois_message["asn_registry"] = record.get("asn_registry")
    if record.get("asn") is not None and record.get("asn", "").isnumeric() is True:
        asn: str = record.get("asn", "")
        whois_message["asn_number"] = int(asn)
    if record.get("asn_country_code") is not None:
        whois_message["asn_country_code"] = record.get("asn_country_code")
    if record.get("asn_date") is not None:
        whois_message["asn_date"] = record.get("asn_date")
    if record.get("asn_description") is not None:
        whois_message["asn_description"] = record.get("asn_description")
    return whois_message


def _get_entity_address(e: dict[str, Any]) -> str | None:
    addresses = e.get("contact", {}).get("address", [])
    if addresses is None:
        return None
    return " ".join(a.get("value") for a in addresses)


def get_ips_from_dns_record_message(
    message: m.Message,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Extract IP address from DNS record messages.

    Args:
        message: DNS Record Message.

    Returns:
        List of IP addresses.
    """
    ip_addresses = []
    if message.data["record"] in ("resolver", "a", "aaaa"):
        try:
            values = [
                ipaddress.ip_address(value) for value in message.data.get("values", [])
            ]
            ip_addresses.extend(values)
        except ipaddress.AddressValueError as e:
            logger.error("%s", e)
    return ip_addresses


def normalize_asn(asn: object) -> str:
    """Normalize an ASN to the canonical ``AS<number>`` form.

    Args:
        asn: ASN value with or without the ``AS`` prefix.

    Returns:
        Canonical ASN value.
    """
    if not isinstance(asn, str):
        raise TypeError(f"Invalid ASN: {asn!r}")
    value = asn.strip()
    if value[:2].lower() == "as":
        value = value[2:]
    if value.isascii() is False or value.isdecimal() is False:
        raise ValueError(f"Invalid ASN: {asn!r}")
    asn_number = int(value)
    if asn_number <= 0 or asn_number > MAX_ASN_NUMBER:
        raise ValueError(f"Invalid ASN: {asn!r}")
    return f"AS{asn_number}"


@tenacity.retry(
    stop=tenacity.stop_after_attempt(RIPE_LOOKUP_ATTEMPTS),
    wait=tenacity.wait_fixed(RIPE_LOOKUP_RETRY_WAIT_SECONDS),
    retry=tenacity.retry_if_exception_type(RipeLookupError),
    reraise=True,
)
def _fetch_ripe_prefixes(normalized_asn: str) -> list[object]:
    """Fetch announced prefixes for an ASN from the public RIPE API."""
    request = urllib.request.Request(
        f"{RIPE_ANNOUNCED_PREFIXES_URL}?resource={normalized_asn}",
        headers={"Accept": "application/json", "User-Agent": RIPE_USER_AGENT},
    )
    try:
        with urllib.request.urlopen(
            request, timeout=RIPE_LOOKUP_TIMEOUT_SECONDS
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (
        http.client.HTTPException,
        OSError,
        UnicodeError,
        ValueError,
    ) as error:
        raise RipeLookupError(f"RIPE lookup failed for {normalized_asn}") from error

    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise RipeLookupError(
            f"RIPE lookup returned an invalid status for {normalized_asn}"
        )
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RipeLookupError(f"RIPE lookup returned invalid data for {normalized_asn}")
    prefixes = data.get("prefixes")
    if not isinstance(prefixes, list):
        raise RipeLookupError(
            f"RIPE lookup returned invalid prefixes for {normalized_asn}"
        )
    return [
        prefix.get("prefix")
        for prefix in prefixes
        if isinstance(prefix, dict) and "prefix" in prefix
    ]


def get_networks_for_normalized_asn(
    normalized_asn: str,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Return normalized, exactly deduplicated prefixes announced by an ASN."""
    return _normalize_networks(_fetch_ripe_prefixes(normalized_asn))


def _normalize_networks(
    cidrs: collections.abc.Iterable[object],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse CIDRs and remove only exact canonical duplicates."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    seen: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for cidr in cidrs:
        if not isinstance(cidr, str):
            logger.warning("ignoring non-string CIDR value: %r", cidr)
            continue
        candidate = cidr.strip()
        if not candidate:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            logger.warning("ignoring invalid network range: %s", candidate)
            continue
        if network not in seen:
            seen.add(network)
            networks.append(network)
    return networks
