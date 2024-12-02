"""WhoisIP agent implementation that processes both DNS records and IP assets."""

import ipaddress
import logging
import re
from typing import Any, Dict, cast

import ipwhois
import tenacity
from ipwhois import exceptions
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

MAX_RETRY_ATTEMPTS = 2
WAIT_BETWEEN_RETRY = 3
IPV4_CIDR_LIMIT = 16
IPV6_CIDR_LIMIT = 112


@tenacity.retry(
    stop=tenacity.stop_after_attempt(MAX_RETRY_ATTEMPTS),
    wait=tenacity.wait_fixed(WAIT_BETWEEN_RETRY),
    retry=tenacity.retry_if_exception_type(ipwhois.exceptions.HTTPLookupError),
    reraise=True,
)
def _get_whois_record(host: str) -> dict[str, Any]:
    logger.info("host: %s", host)
    lookup_rdap = ipwhois.IPWhois(host).lookup_rdap()
    return cast(dict[str, Any], lookup_rdap)


class WhoisIPAgent(agent.Agent, persist_mixin.AgentPersistMixin):
    """WhoisIP agent that collect IP registry and AS information using the RDAP protocol."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_domain_regex: str | None = self.args.get("scope_domain_regex")

    def process(self, message: m.Message) -> None:
        """Process DNS records and IP asset to emit whois record.

        Args:
            message: DNS record or IP asset message.

        Returns:
            None
        """
        logger.info("processing message of selector %s", message.selector)
        if message.selector.startswith("v3.asset.domain_name.dns_record"):
            return self._process_dns_record(message)
        host = message.data.get("host")
        if host is not None:
            return self._process_ip(message, host)

    def _is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is in the scan scope with a regular expression."""
        if self._scope_domain_regex is None:
            return True
        domain_in_scope = re.match(self._scope_domain_regex, domain)
        if domain_in_scope is None:
            logger.warning(
                "Domain %s is not in scanning scope %s",
                domain,
                self._scope_domain_regex,
            )
            return False
        else:
            return True

    def _process_dns_record(self, message: m.Message) -> None:
        domain = message.data["name"]
        is_domain_in_scope = self._is_domain_in_scope(domain)
        if is_domain_in_scope is False:
            return

        ip_addresses = ipwhois_data_handler.get_ips_from_dns_record_message(message)
        for ip in ip_addresses:
            host = str(ip)
            if self.set_add("agent_whois_ip_asset", host):
                logger.info("processing ip %s", host)
                try:
                    record = _get_whois_record(host)
                    whois_message = ipwhois_data_handler.prepare_whois_message_data(
                        ip, record
                    )
                    self._emit_whois_message(whois_message)
                except (
                    ipwhois.exceptions.IPDefinedError,
                    ipwhois.exceptions.HTTPLookupError,
                    ipwhois.exceptions.ASNRegistryError,
                ):
                    # Case where of the loopback address.
                    logger.warning(
                        "some data not found when agent_whois_ip_asset try to process IP "
                    )
            else:
                logger.info("target %s was processed before, exiting", host)
                return

    def _process_ip(self, message: m.Message, host: str) -> None:
        mask = message.data.get("mask")
        if mask is None:
            network = ipaddress.ip_network(host)
        else:
            version = message.data.get("version")
            if version is None:
                try:
                    ip = ipaddress.ip_address(host)
                    version = ip.version
                except ValueError:
                    raise ValueError(f"Invalid IP address: {host}")
            if version not in (4, 6):
                raise ValueError(f"Incorrect ip version {version}.")
            elif version == 4 and int(mask) < IPV4_CIDR_LIMIT:
                raise ValueError(
                    f"Subnet mask below {IPV4_CIDR_LIMIT} is not supported."
                )
            elif version == 6 and int(mask) < IPV6_CIDR_LIMIT:
                raise ValueError(
                    f"Subnet mask below {IPV6_CIDR_LIMIT} is not supported."
                )
            network = ipaddress.ip_network(f"{host}/{mask}", strict=False)

        if self.add_ip_network("agent_whois_ip_asset", network):
            for address in network.hosts():
                try:
                    logger.info("processing IP %s", address)
                    record = _get_whois_record(host=str(address))
                    whois_message = ipwhois_data_handler.prepare_whois_message_data(
                        address, record
                    )
                    self._emit_whois_message(whois_message)
                except (
                    ipwhois.exceptions.IPDefinedError,
                    ipwhois.exceptions.ASNRegistryError,
                    ipwhois.exceptions.HTTPLookupError,
                    ipwhois.exceptions.ASNParseError,
                ):
                    # Case where of the loopback address.
                    logger.error(
                        "Some data not found when agent_whois_ip_asset try to process IP %s",
                        address,
                    )
                except exceptions.HTTPRateLimitError:
                    logger.info("Rate limit error for IP %s", address)
        else:
            logger.info("target %s was processed before, exiting", network)
            return

    def _emit_whois_message(self, whois_message: Dict[str, Any]) -> None:
        """Emit the whois message depending on the type of host address"""
        if (version := whois_message.get("version")) is not None:
            if version == 4:
                self.emit("v3.asset.ip.v4.whois", whois_message)
            elif version == 6:
                self.emit("v3.asset.ip.v6.whois", whois_message)


if __name__ == "__main__":
    logger.info("starting agent ...")
    WhoisIPAgent.main()
