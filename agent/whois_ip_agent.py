"""WhoisIP agent implementation"""
import ipaddress
import logging
from typing import Any, Dict

import ipwhois
import tenacity
from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from rich import logging as rich_logging

from agent import ipwhois_data_handler

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)
MAX_RETRY_ATTEMPTS = 5
WAIT_BETWEEN_RETRY = 3


@tenacity.retry(
    stop=tenacity.stop_after_attempt(MAX_RETRY_ATTEMPTS),
    wait=tenacity.wait_fixed(WAIT_BETWEEN_RETRY),
    retry=tenacity.retry_if_exception_type(ipwhois.exceptions.HTTPLookupError),
    reraise=True,
)
def _get_wohis_record(host: str):
    return ipwhois.IPWhois(host).lookup_rdap()


class WhoisIPAgent(agent.Agent, persist_mixin.AgentPersistMixin):
    """WhoisIP agent that collect IP registry and AS information using the RDAP protocol."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: m.Message) -> None:
        logger.info("Processing message of selector : %s", message.selector)

        if message.selector == "v3.asset.domain_name.dns_record":
            ip_addresses = ipwhois_data_handler.get_ips_from_dns_record_message(message)

            for ip in ip_addresses:
                host = str(ip)
                if not self.set_add("agent_whois_ip_asset", host):
                    logger.info("target %s was processed before, exiting", host)
                    return
                mask = "32"
                version = ip.version
                logger.info("processing IP %s", host)
                try:
                    record = _get_wohis_record(host=host)
                    logger.debug("record\n%s", record)
                    whois_message = ipwhois_data_handler.prepare_whois_message_data(
                        host, mask, version, record
                    )
                    self._emit_whois_message(version, whois_message)
                except (
                    ipwhois.exceptions.IPDefinedError,
                    ipwhois.exceptions.HTTPLookupError,
                ) as e:
                    # casewhere of loopback address
                    logger.error("%s", e)

        else:
            host = message.data.get("host")
            mask = message.data.get("mask")

            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                if not self.add_ip_network("agent_whois_ip_asset", addresses):
                    logger.info("target %s was processed before, exiting", addresses)
                    return
            else:
                if not self.set_add("agent_whois_ip_asset", host):
                    logger.info("target %s was processed before, exiting", host)
                    return
                addresses = ipaddress.ip_network(host)

            for address in addresses.hosts():
                try:
                    logger.info("processing IP %s", address)
                    record = _get_wohis_record(host=str(address))
                    version = message.data.get("version")
                    whois_message = ipwhois_data_handler.prepare_whois_message_data(
                        str(address), mask, version, record
                    )
                    self._emit_whois_message(version, whois_message)
                except (
                    ipwhois.exceptions.ASNRegistryError,
                    ipwhois.exceptions.IPDefinedError,
                    ipwhois.exceptions.HTTPLookupError,
                ) as e:
                    # casewhere of loopback address
                    logger.error("%s", e)

    def _emit_whois_message(self, version: int, whois_message: Dict[str, Any]) -> None:
        """Emit the whois message depending on the type of host address"""
        if version == 4:
            self.emit("v3.asset.ip.v4.whois", whois_message)
        elif version == 6:
            self.emit("v3.asset.ip.v6.whois", whois_message)
        else:
            logger.error("unsupported version %s", version)


if __name__ == "__main__":
    logger.info("starting agent ...")
    WhoisIPAgent.main()
