"""Helper module for preparing the whois IP messages."""
import ipaddress
import logging
from typing import Any, Dict, Union, Optional, List

from ostorlab.agent.message import message as m

logger = logging.getLogger(__name__)


def prepare_whois_message_data(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, record: Dict[str, Any]) -> Dict[
    str, Any]:
    """Prepares data of the whois IP message."""

    whois_message: Dict[str, Any] = {
        'host': str(ip),
        'mask': str(ip.max_prefixlen),
        'version': ip.version,
        'network': {
            'cidr': record.get('network', {}).get('cidr'),
            'name': record.get('network', {}).get('name'),
            'handle': record.get('network', {}).get('handle'),
            'parent_handle': record.get('network', {}).get('parent_handle'),
        },
        'entities': [
            {
                'name': e.get('handle'),
                'contact': {
                    'name': e.get('contact', {}).get('name'),
                    'kind': e.get('contact', {}).get('kind'),
                    'address': _get_entity_address(e),
                }
            } for e in record.get('objects', {}).values()
        ],
    }

    if record.get('asn_registry') is not None:
        whois_message['asn_registry'] = record.get('asn_registry')
    if record.get('asn') is not None and record.get('asn', '').isnumeric() is True:
        asn: str = record.get('asn', '')
        whois_message['asn_number'] = int(asn)
    if record.get('asn_country_code') is not None:
        whois_message['asn_country_code'] = record.get('asn_country_code')
    if record.get('asn_date') is not None:
        whois_message['asn_date'] = record.get('asn_date')
    if record.get('asn_description') is not None:
        whois_message['asn_description'] = record.get('asn_description')
    return whois_message


def _get_entity_address(e: Dict[str, Any]) -> Optional[str]:
    addresses = e.get('contact', {}).get('address', [])
    if addresses is None:
        return None
    return ' '.join(a.get('value') for a in addresses)


def get_ips_from_dns_record_message(message: m.Message) -> List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    ip_addresses = []
    if message.data['record'] in ('resolver', 'a', 'aaaa'):
        try:
            values = [ipaddress.ip_address(value) for value in message.data.get('values', [])]
            ip_addresses.extend(values)
        except ipaddress.AddressValueError as e:
            logger.error('%s', e)
    return ip_addresses
