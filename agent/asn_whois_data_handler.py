"""Helper module for the whois record of an ASN, read from RDAP autnum."""

import logging
import urllib.parse
from typing import Any

import pycountry
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

# vCard `kind` of an organisation (RFC 6350), the other kinds are individual, group and location.
VCARD_KIND_ORGANISATION = "org"


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
    country_code = record.get("country")
    if country_code is None:
        country_code = _registrant_country_code(record)
    if country_code is not None:
        whois_message["country_code"] = country_code
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
    """Name of the registrant organisation, from its vCard `fn`.

    The name is only returned when the vCard `kind` is `org`: the registrant can be a person,
    and the name of a person is personal data that the message must not carry.
    """
    vcard = _registrant_vcard(record)
    kinds = [field[3] for field in vcard if len(field) > 3 and field[0] == "kind"]
    if VCARD_KIND_ORGANISATION not in kinds:
        return None
    for field in vcard:
        if len(field) > 3 and field[0] == "fn":
            name: str = field[3]
            return name
    return None


def _registrant_country_code(record: dict[str, Any]) -> str | None:
    """Country code of the registrant, from the last line of its vCard address.

    ARIN and RIPE records have no `country`: the country is only written at the end of the
    registrant address label, e.g. `United States` or `NETHERLANDS`.
    """
    for field in _registrant_vcard(record):
        if len(field) < 2 or field[0] != "adr" or isinstance(field[1], dict) is False:
            continue
        label = field[1].get("label")
        if isinstance(label, str) is False or label.strip() == "":
            continue
        country_name = label.strip().splitlines()[-1].strip()
        try:
            country: Any = pycountry.countries.lookup(country_name)
        except LookupError:
            logger.info("unknown registrant country %s", country_name)
            return None
        country_code: str = country.alpha_2
        return country_code
    return None


def _registrant_vcard(record: dict[str, Any]) -> list[Any]:
    """vCard properties of the registrant entity, empty when the record has none."""
    for entity in _list_field(record, "entities"):
        if "registrant" not in _list_field(entity, "roles"):
            continue
        vcard = _list_field(entity, "vcardArray")
        if len(vcard) < 2 or vcard[1] is None:
            continue
        properties: list[Any] = vcard[1]
        return properties
    return []


def _list_field(data: dict[str, Any], key: str) -> list[Any]:
    """List value of `key`, empty when the key is missing or null."""
    value: list[Any] | None = data.get(key)
    if value is None:
        return []
    return value
