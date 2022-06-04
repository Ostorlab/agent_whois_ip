"""Helper module for preparing the whosis IP messages."""
from typing import Any, Dict, Union
import logging
import ipaddress

from ostorlab.agent import message as m

logger = logging.getLogger(__name__)

def prepare_whois_message_data(host: str, mask: str, version: int, record) -> Dict[str, Any]:
    """Prepares data of the whois IP message."""
    whois_message = {
        'host': host,
        'mask': mask,
        'version': version,
        'asn_registry': record.get('asn_registry'),
        'asn_number': int(record.get('asn')),
        'asn_country_code': record.get('asn_country_code'),
        'asn_date': record.get('asn_date'),
        'asn_description': record.get('asn_description'),
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
    return whois_message

def _get_entity_address(e):
    addresses = e.get('contact', {}).get('address', [])
    if addresses is None:
        return None
    return ' '.join(a.get('value') for a in addresses)

def get_ips_from_dns_record_message(message: m.Message) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    ip_addresses = []
    if message.data['record'] in ('resolver', 'a', 'aaaa'):
        try:
            values = [ipaddress.ip_address(value) for value in message.data.get('values', [])]
            ip_addresses.extend(values)
        except ipaddress.AddressValueError as e:
            logger.error('%s', e)
    return ip_addresses
