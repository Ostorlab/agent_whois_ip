"""WhoisIP agent implementation that processes both DNS records and IP assets."""

import ipaddress
import logging
import re
from typing import Any, cast

import ipwhois
import redis
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
ASN_SELECTOR = "v3.asset.asn"
ASN_PROCESSED_SET = "agent_whois_ip_asn_asset"
ASN_CLAIM_KEY_PREFIX = "agent_whois_ip_asn_claim"
NETWORK_PROCESSED_SET = "agent_whois_ip_network_asset"
NETWORK_CLAIM_KEY_PREFIX = "agent_whois_ip_network_claim"


class Error(Exception):
    """Base error for the whois IP agent module."""


class NetworkClaimError(Error):
    """Raised when another worker is currently emitting the same network."""


@tenacity.retry(
    stop=tenacity.stop_after_attempt(MAX_RETRY_ATTEMPTS),
    wait=tenacity.wait_fixed(WAIT_BETWEEN_RETRY),
    retry=tenacity.retry_if_exception_type(ipwhois.exceptions.HTTPLookupError),
    reraise=True,
)
def _get_whois_record(host: str) -> dict[str, Any]:
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
        """Process DNS records, IP assets, and ASN assets.

        Args:
            message: DNS record, IP asset, or ASN asset message.

        Returns:
            None
        """
        logger.debug("processing message of selector %s", message.selector)
        if message.selector == ASN_SELECTOR:
            return self._process_asn(message.data.get("asn"))
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
                ):
                    # Case where of the loopback address.
                    logger.warning(
                        "Some data not found when agent_whois_ip_asset try to process IP %s",
                        address,
                    )
                except ipwhois.exceptions.ASNParseError:
                    logger.error("ASN parse error for IP %s", address)
                except exceptions.HTTPRateLimitError:
                    logger.warning("Rate limit error for IP %s", address)
        else:
            logger.info("target %s was processed before, exiting", network)
            return

    def _process_asn(self, asn: object) -> None:
        """Expand an ASN into the network ranges it currently announces."""
        try:
            normalized_asn = ipwhois_data_handler.normalize_asn(asn)
        except (TypeError, ValueError):
            logger.warning("invalid ASN value: %r", asn)
            return

        if self.set_is_member(ASN_PROCESSED_SET, normalized_asn):
            logger.info("ASN %s was processed before, exiting", normalized_asn)
            return

        claim_key = f"{ASN_CLAIM_KEY_PREFIX}:{normalized_asn}"
        if self.set_add(claim_key, normalized_asn) is False:
            logger.info("ASN %s is already being processed", normalized_asn)
            return

        try:
            if self.set_is_member(ASN_PROCESSED_SET, normalized_asn):
                return
            networks = ipwhois_data_handler.get_networks_for_normalized_asn(
                normalized_asn
            )
            contended_cidrs: list[str] = []
            for network in networks:
                try:
                    self._emit_network_message(network)
                except NetworkClaimError:
                    contended_cidrs.append(network.with_prefixlen)

            if len(contended_cidrs) > 0:
                raise NetworkClaimError(
                    f"networks {', '.join(contended_cidrs)} are already being emitted"
                )

            self.set_add(ASN_PROCESSED_SET, normalized_asn)
        finally:
            try:
                self.delete(claim_key)
            except redis.exceptions.RedisError:
                logger.exception("failed to release ASN claim for %s", normalized_asn)

    def _emit_network_message(
        self, network: ipaddress.IPv4Network | ipaddress.IPv6Network
    ) -> None:
        """Emit one network message without enumerating any addresses."""
        cidr = network.with_prefixlen
        if self.set_is_member(NETWORK_PROCESSED_SET, cidr):
            logger.info("network %s was emitted before, exiting", cidr)
            return

        claim_key = f"{NETWORK_CLAIM_KEY_PREFIX}:{cidr}"
        if self.set_add(claim_key, cidr) is False:
            if self.set_is_member(NETWORK_PROCESSED_SET, cidr):
                return
            raise NetworkClaimError(f"network {cidr} is already being emitted")

        try:
            if self.set_is_member(NETWORK_PROCESSED_SET, cidr):
                return
            data = {
                "ips": [
                    {
                        "host": str(network.network_address),
                        "mask": str(network.prefixlen),
                        "version": network.version,
                    }
                ]
            }
            self.emit("v3.asset.network", data)
            self.set_add(NETWORK_PROCESSED_SET, cidr)
        finally:
            try:
                self.delete(claim_key)
            except redis.exceptions.RedisError:
                logger.exception("failed to release network claim for %s", cidr)

    def _emit_whois_message(self, whois_message: dict[str, Any]) -> None:
        """Emit the whois message depending on the type of host address"""
        if (version := whois_message.get("version")) is not None:
            if version == 4:
                self.emit("v3.asset.ip.v4.whois", whois_message)
            elif version == 6:
                self.emit("v3.asset.ip.v6.whois", whois_message)


if __name__ == "__main__":
    logger.info("starting agent ...")
    WhoisIPAgent.main()
