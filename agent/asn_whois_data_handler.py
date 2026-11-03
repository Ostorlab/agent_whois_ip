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


class RetryableRDAPError(Exception):
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
    if record.get("name"):
        whois_message["name"] = record["name"]
    org = _registrant_name(record)
    if org is not None:
        whois_message["org"] = org
    if record.get("country"):
        whois_message["country_code"] = record["country"]
    events = {
        event.get("eventAction"): event.get("eventDate", "")
        for event in record.get("events", [])
    }
    if events.get("registration"):
        whois_message["allocated_date"] = events["registration"][:10]
    if events.get("last changed"):
        whois_message["updated_date"] = events["last changed"][:10]
    rdap_url = next(
        (
            link.get("href")
            for link in record.get("links", [])
            if link.get("rel") == "self"
        ),
        None,
    )
    if rdap_url is not None:
        whois_message["rdap_url"] = rdap_url
    registry = _registry(rdap_url, record.get("port43"))
    if registry is not None:
        whois_message["registry"] = registry
    return whois_message


def _registry(rdap_url: str | None, port43: str | None) -> str | None:
    """Registry holding the ASN, from the host of its RDAP record or of its whois server."""
    rdap_host = urllib.parse.urlparse(rdap_url).hostname if rdap_url else None
    hosts = [rdap_host or "", port43 or ""]
    for host in hosts:
        for domain, registry in REGISTRIES.items():
            if host == domain or host.endswith(f".{domain}"):
                return registry
    return None


def _registrant_name(record: dict[str, Any]) -> str | None:
    """Name of the registrant organisation, from its vCard `fn`."""
    for entity in record.get("entities", []):
        if "registrant" not in entity.get("roles", []):
            continue
        vcard = entity.get("vcardArray", [None, []])
        for field in vcard[1] if len(vcard) > 1 else []:
            if len(field) > 3 and field[0] == "fn":
                name: str = field[3]
                return name
    return None
