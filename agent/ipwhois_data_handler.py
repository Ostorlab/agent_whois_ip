"""Helper module for preparing the whois IP and ASN messages."""

import ipaddress
import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Union

import tenacity
from ostorlab.agent.message import message as m

logger = logging.getLogger(__name__)

RIPE_ANNOUNCED_PREFIXES_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_LOOKUP_TIMEOUT = 15
RIPE_LOOKUP_RETRY_COUNT = 2
RIPE_LOOKUP_WAIT_BETWEEN_RETRY = 3
RIPE_USER_AGENT = "agent_whois_ip"


class RipeLookupError(Exception):
    """Raised when the RIPE announced-prefixes lookup fails."""


def prepare_whois_message_data(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, record: Dict[str, Any]
) -> Dict[str, Any]:
    """Prepares data of the whois IP message.

    Args:
        ip: IP address target of the whois data.
        record: Whois data records.

    Returns:
        Dict whois message.
    """

    whois_message: Dict[str, Any] = {
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


def _get_entity_address(e: Dict[str, Any]) -> Optional[str]:
    addresses = e.get("contact", {}).get("address", [])
    if addresses is None:
        return None
    return " ".join(a.get("value") for a in addresses)


def get_ips_from_dns_record_message(
    message: m.Message,
) -> List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
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


def normalize_asn(asn: str) -> str:
    """Normalize an ASN value to the ``AS<number>`` form.

    The RIPE announced-prefixes API accepts the ASN with or without the
    leading ``AS`` prefix; the normalized form is used for deduplication and
    for a consistent lookup resource.

    Args:
        asn: The ASN, with or without the leading ``AS`` prefix.

    Returns:
        The normalized ASN string.

    Raises:
        ValueError: If the ASN does not contain a numeric component.
    """
    trimmed = asn.strip()
    if trimmed.lower().startswith("as"):
        number_part = trimmed[2:]
    else:
        number_part = trimmed
    if number_part.isnumeric() is False:
        raise ValueError(f"Invalid ASN: {asn}")
    return f"AS{number_part}"


@tenacity.retry(
    stop=tenacity.stop_after_attempt(RIPE_LOOKUP_RETRY_COUNT),
    wait=tenacity.wait_fixed(RIPE_LOOKUP_WAIT_BETWEEN_RETRY),
    retry=tenacity.retry_if_exception_type(RipeLookupError),
    reraise=True,
)
def _fetch_ripe_prefixes(resource: str) -> list[str]:
    """Fetch the announced prefixes for a resource from the RIPE stat API.

    The public RIPE announced-prefixes data endpoint is queried without
    authentication. Network errors and non-ok responses are retried; lookup
    failures remain retryable by the caller.

    Args:
        resource: The ASN resource to look up (e.g. ``AS268302``).

    Returns:
        List of announced prefix strings.

    Raises:
        RipeLookupError: If the lookup fails after retries.
    """
    url = f"{RIPE_ANNOUNCED_PREFIXES_URL}?resource={resource}"
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": RIPE_USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=RIPE_LOOKUP_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError) as e:
        raise RipeLookupError(f"RIPE lookup failed for {resource}") from e
    if not isinstance(payload, dict):
        raise RipeLookupError("RIPE lookup returned invalid payload")
    if payload.get("status") != "ok":
        raise RipeLookupError(f"RIPE lookup returned status {payload.get('status')!r}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RipeLookupError("RIPE lookup returned invalid data")
    prefixes = data.get("prefixes")
    if not isinstance(prefixes, list):
        raise RipeLookupError("RIPE lookup returned invalid prefixes")
    return [
        str(prefix["prefix"])
        for prefix in prefixes
        if isinstance(prefix, dict) and prefix.get("prefix")
    ]


def get_networks_for_asn(
    asn: str,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Look up the IPv4 and IPv6 network ranges announced by an ASN.

    Queries the public RIPE announced-prefixes API (no authentication) and
    returns the announced prefixes normalized and deduplicated.

    Args:
        asn: The ASN, with or without the leading ``AS`` prefix.

    Returns:
        Deduplicated list of announced networks, preserving IPv4 and IPv6
        ranges as returned by RIPE.

    Raises:
        RipeLookupError: If the RIPE lookup fails after retries.
        ValueError: If the ASN is invalid.
    """
    normalized_asn = normalize_asn(asn)
    prefixes = _fetch_ripe_prefixes(normalized_asn)
    return _normalize_networks(prefixes)


def _normalize_networks(
    cidrs: list[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse and deduplicate network ranges from a list of CIDR strings.

    Args:
        cidrs: Raw CIDR strings (e.g. announced prefixes).

    Returns:
        Deduplicated list of parsed networks.
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    seen: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for cidr_str in cidrs:
        candidate = cidr_str.strip()
        if len(candidate) == 0:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            logger.warning("ignoring invalid network range: %s", candidate)
            continue
        if network in seen:
            continue
        seen.add(network)
        networks.append(network)
    return networks
