"""WhoisIP agent implementation"""
import logging
from rich import logging as rich_logging
import ipwhois
from ostorlab.agent import agent
from ostorlab.agent import message as m

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    level='INFO',
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)


class WhoisIPAgent(agent.Agent):
    """WhoisIP agent that collect IP registry and AS information using the RDAP protocol."""

    def process(self, message: m.Message) -> None:
        logger.info('processing IP %s', message.data.get('host'))
        record = ipwhois.IPWhois(message.data.get('host')).lookup_rdap()
        logger.debug('record\n%s', record)

        whois_message = {
            'host': message.data.get('host'),
            'mask': message.data.get('mask'),
            'version': message.data.get('version'),
            'asn_registry': record.get('asn_registry'),
            'asn_number': record.get('asn_number'),
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
                        'address': self._get_entity_address(e),
                    }
                } for e in record.get('objects', {}).values()
            ],

        }

        if message.data.get('version') == 4:
            self.emit('v3.asset.ip.v4.whois', whois_message)
        elif message.data.get('version') == 6:
            self.emit('v3.asset.ip.v6.whois', whois_message)
        else:
            logger.error('unsupported version %s', message.data.get('version'))

    def _get_entity_address(self, e):
        addresses = e.get('contact', {}).get('address', [])
        if addresses is None:
            return None
        return ' '.join(a.get('value') for a in addresses)


if __name__ == '__main__':
    logger.info('starting agent ...')
    WhoisIPAgent.main()
