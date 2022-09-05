"""WhoisIP agent implementation that processes both DNS records and IP assets."""
import ipaddress
import logging
from typing import Any, Dict

import ipwhois
from ipwhois import exceptions
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import ipwhois_data_handler

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    level='INFO',
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)


class WhoisIPAgent(agent.Agent, persist_mixin.AgentPersistMixin):
    """WhoisIP agent that collect IP registry and AS information using the RDAP protocol."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: m.Message) -> None:
        """Process DNS records and IP asset to emit whois record.

        Args:
            message: DNS record or IP asset message.

        Returns:
            None
        """
        logger.debug('processing message of selector %s', message.selector)

        if message.selector.startswith('v3.asset.domain_name.dns_record'):
            return self._process_dns_record(message)
        else:
            return self._process_ip(message)

    def _process_dns_record(self, message: m.Message) -> None:
        ip_addresses = ipwhois_data_handler.get_ips_from_dns_record_message(message)
        for ip in ip_addresses:
            host = str(ip)
            if self.set_add('agent_whois_ip_asset', host):
                logger.info('processing ip %s', host)
                try:
                    record = ipwhois.IPWhois(host).lookup_rdap()
                    whois_message = ipwhois_data_handler.prepare_whois_message_data(ip, record)
                    self._emit_whois_message(whois_message)
                except ipwhois.exceptions.IPDefinedError:
                    # Case where of the loopback address.
                    logger.warning('some data not found when agent_whois_ip_asset try to process IP ')
            else:
                logger.info('target %s was processed before, exiting', host)
                return

    def _process_ip(self, message: m.Message) -> None:
        host = message.data.get('host')
        mask = message.data.get('mask')
        network = ipaddress.ip_network(f'{host}/{mask}',
                                       strict=False) if mask is not None else ipaddress.ip_network(f'{host}')

        if self.add_ip_network('agent_whois_ip_asset', network):
            for address in network.hosts():
                try:
                    logger.info('processing IP %s', address)
                    record = ipwhois.IPWhois(str(address)).lookup_rdap()
                    whois_message = ipwhois_data_handler.prepare_whois_message_data(address, record)
                    self._emit_whois_message(whois_message)
                except (ipwhois.exceptions.IPDefinedError, ipwhois.exceptions.ASNRegistryError):
                    # Case where of the loopback address.
                    logger.warning('Some data not found when agent_whois_ip_asset try to process IP %s', address)
                except exceptions.HTTPRateLimitError:
                    logger.warning('Rate limit error for IP %s', address)
        else:
            logger.info('target %s was processed before, exiting', network)
            return

    def _emit_whois_message(self, whois_message: Dict[str, Any]) -> None:
        """Emit the whois message depending on the type of host address"""
        if (version := whois_message.get('version')) is not None:
            if version == 4:
                self.emit('v3.asset.ip.v4.whois', whois_message)
            elif version == 6:
                self.emit('v3.asset.ip.v6.whois', whois_message)


if __name__ == '__main__':
    logger.info('starting agent ...')
    WhoisIPAgent.main()
