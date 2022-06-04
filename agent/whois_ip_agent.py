"""WhoisIP agent implementation"""
import logging
from typing import Any, Dict
from rich import logging as rich_logging
import ipwhois
from ostorlab.agent import agent
from ostorlab.agent import message as m

from agent import ipwhois_data_handler

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
        if message.selector == 'v3.asset.domain_name.dns_record':
            ip_addresses = ipwhois_data_handler.get_ips_from_dns_record_message(message)

            for ip in ip_addresses:
                host = str(ip)
                mask = '/32'
                version = ip.version
                logger.info('processing IP %s', host)
                try:
                    record = ipwhois.IPWhois(host).lookup_rdap()
                    logger.debug('record\n%s', record)
                    whois_message = ipwhois_data_handler.prepare_whois_message_data(host, mask, version, record)
                    self._emit_whois_message(version, whois_message)
                except ipwhois.exceptions.IPDefinedError as e:
                    # casewhere of loopback address
                    logger.error('%s', e)

        else:
            logger.info('processing IP %s', message.data.get('host'))
            try:
                record = ipwhois.IPWhois(message.data.get('host')).lookup_rdap()
                host = message.data.get('host')
                mask = message.data.get('mask')
                version = message.data.get('version')
                whois_message = ipwhois_data_handler.prepare_whois_message_data(host, mask, version, record)
                self._emit_whois_message(version, whois_message)
            except ipwhois.exceptions.IPDefinedError as e:
                # casewhere of loopback address
                logger.error('%s', e)


    def _emit_whois_message(self, version: int, whois_message: Dict[str, Any]) -> None:
        """Emit the whois message depending on the type of host address"""
        if version == 4:
            self.emit('v3.asset.ip.v4.whois', whois_message)
        elif version == 6:
            self.emit('v3.asset.ip.v6.whois', whois_message)
        else:
            logger.error('unsupported version %s', version)


if __name__ == '__main__':
    logger.info('starting agent ...')
    WhoisIPAgent.main()
