"""Helper module for the whois record of an ASN, read from RDAP autnum."""

import logging
import urllib.parse
from typing import Any

import requests
import tenacity

logger = logging.getLogger(__name__)

RDAP_AUTNUM_URL = "https://rdap.org/autnum/{asn}"
REQUEST_TIMEOUT = 30
MAX_RETRY_ATTEMPTS = 2
WAIT_BETWEEN_RETRY = 3
# Same registry names as the IP whois messages (ipwhois `asn_registry`), keyed by the
# domain of the RDAP server that answered. registro.br is the Brazilian registry under LACNIC.
REGISTRIES = {
    "arin.net": "arin",
    "ripe.net": "ripencc",
    "apnic.net": "apnic",
    "lacnic.net": "lacnic",
    "registro.br": "lacnic",
    "afrinic.net": "afrinic",
}


class Error(Exception):
    """Base exception of the ASN whois lookup."""


class RetryableRDAPError(Error):
    """RDAP server error or rate limit, worth retrying."""


@tenacity.retry(
    stop=tenacity.stop_after_attempt(MAX_RETRY_ATTEMPTS),
    wait=tenacity.wait_fixed(WAIT_BETWEEN_RETRY),
    retry=tenacity.retry_if_exception_type(
        (requests.ConnectionError, requests.Timeout, RetryableRDAPError)
    ),
    reraise=True,
)
def get_asn_record(asn: str) -> dict[str, Any] | None:
    """RDAP autnum record of `asn`, or None if no registry knows it.

    rdap.org redirects to the RDAP server of the registry that holds the ASN.
    """
    response = requests.get(RDAP_AUTNUM_URL.format(asn=asn), timeout=REQUEST_TIMEOUT)
    if response.status_code == 404:
        return None
    if response.status_code == 429 or response.status_code >= 500:
        raise RetryableRDAPError(f"RDAP answered {response.status_code} for AS{asn}")
    response.raise_for_status()
    record: dict[str, Any] = response.json()
    return record


def prepare_asn_whois_message_data(asn: str, record: dict[str, Any]) -> dict[str, Any]:
    """Prepares data of the `v3.asset.asn.whois` message.

    Personal contacts are left out: the message links to the full record with `rdap_url`.

    Args:
        asn: ASN without the `AS` prefix, e.g. `15169`.
        record: RDAP autnum record.

    Returns:
        Dict whois message.
    """
    whois_message: dict[str, Any] = {"asn": asn}
    if record.get("name") is not None:
        whois_message["name"] = record["name"]
    org = _registrant_name(record)
    if org is not None:
        whois_message["org"] = org
    if record.get("country") is not None:
        whois_message["country_code"] = record["country"]
    events = {
        event.get("eventAction"): event.get("eventDate")
        for event in _list_field(record, "events")
    }
    if events.get("registration") is not None:
        whois_message["allocated_date"] = events["registration"][:10]
    if events.get("last changed") is not None:
        whois_message["updated_date"] = events["last changed"][:10]
    rdap_url = next(
        (
            link.get("href")
            for link in _list_field(record, "links")
            if link.get("rel") == "self"
        ),
        None,
    )
    if rdap_url is not None:
        whois_message["rdap_url"] = rdap_url
        registry = _registry(rdap_url)
        if registry is not None:
            whois_message["registry"] = registry
    return whois_message


def _registry(rdap_url: str) -> str | None:
    """Registry holding the ASN, from the host of its RDAP record."""
    host = urllib.parse.urlparse(rdap_url).hostname
    if host is None:
        return None
    for domain, registry in REGISTRIES.items():
        if host == domain or host.endswith(f".{domain}"):
            return registry
    return None


def _registrant_name(record: dict[str, Any]) -> str | None:
    """Name of the registrant organisation, from its vCard `fn`."""
    for entity in _list_field(record, "entities"):
        if "registrant" not in _list_field(entity, "roles"):
            continue
        vcard = _list_field(entity, "vcardArray")
        if len(vcard) < 2 or vcard[1] is None:
            continue
        for field in vcard[1]:
            if len(field) > 3 and field[0] == "fn":
                name: str = field[3]
                return name
    return None


def _list_field(data: dict[str, Any], key: str) -> list[Any]:
    """List value of `key`, empty when the key is missing or null."""
    value: list[Any] | None = data.get(key)
    if value is None:
        return []
    return value
