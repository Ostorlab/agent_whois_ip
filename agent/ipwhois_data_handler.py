"""Helper module for preparing the whois IP and ASN messages."""

import ipaddress
import logging
from typing import Any, Dict, Union, Optional, List

import ipwhois
import ipwhois.asn
import ipwhois.net
from ostorlab.agent.message import message as m

logger = logging.getLogger(__name__)

ASN_ORIGIN_LOOKUP_RETRY_COUNT = 2
ASN_ORIGIN_NET_PLACEHOLDER_HOST = "1.0.0.0"


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
    """Normalize an ASN value to the ``AS<number>`` form expected by whois.

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
    if number_part.isnumeric() is False or len(number_part) == 0:
        raise ValueError(f"Invalid ASN: {asn}")
    return f"AS{number_part}"


def get_networks_for_asn(
    asn: str,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Look up the IPv4 and IPv6 network ranges announced by an ASN.

    Args:
        asn: The ASN, with or without the leading ``AS`` prefix.

    Returns:
        Deduplicated list of announced networks, preserving IPv4 and IPv6
        ranges as returned by the registry.
    """
    normalized_asn = normalize_asn(asn)
    net = ipwhois.net.Net(ASN_ORIGIN_NET_PLACEHOLDER_HOST)
    record = ipwhois.asn.ASNOrigin(net).lookup(
        asn=normalized_asn, retry_count=ASN_ORIGIN_LOOKUP_RETRY_COUNT
    )
    return _normalize_networks(record.get("nets", []))


def _normalize_networks(
    nets: list[dict[str, Any]],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse and deduplicate network ranges from ASN origin lookup results.

    Args:
        nets: Raw network entries returned by the ASN origin lookup.

    Returns:
        Deduplicated list of parsed networks.
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    seen: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for entry in nets:
        cidr = entry.get("cidr")
        if cidr is None:
            continue
        for cidr_str in str(cidr).split(","):
            cidr_str = cidr_str.strip()
            if len(cidr_str) == 0:
                continue
            try:
                network = ipaddress.ip_network(cidr_str, strict=False)
            except ValueError:
                logger.warning("ignoring invalid network range: %s", cidr_str)
                continue
            if network in seen:
                continue
            seen.add(network)
            networks.append(network)
    return networks
