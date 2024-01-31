import asyncio
import logging
import socket
import struct
import threading
from collections import Counter
from datetime import datetime, timedelta
from functools import lru_cache
from ipaddress import ip_address
from typing import Union

import pcap
from dpkt.dpkt import NeedData
from dpkt.ethernet import ETH_TYPE_ARP, ETH_TYPE_IP, ETH_TYPE_IP6, Ethernet
from dpkt.icmp import ICMP
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.sll import SLL

from ..models import Finding
from .probe import Probe

_LOGGER = logging.getLogger(__name__)


# From https://stackoverflow.com/a/37005235
prefix = "IPPROTO_"
PROTOMAP = {
    num: name[len(prefix) :]
    for name, num in vars(socket).items()
    if name.startswith(prefix)
}


@lru_cache(maxsize=4096)
def get_ip(x):
    return ip_address(x)


class PCAPSniffer(Probe):
    """Passive sniffing for IP addresses."""

    def __init__(self, *, prober=None, config=None, **kwargs):
        super().__init__(prober=prober, config=config, **kwargs)
        self._should_quit = threading.Event()

        self.prober = prober
        self._sniffer = None
        self._sniffer_task = None
        self.stats = Counter()
        self.summary = {}

    async def run(self) -> Probe:
        loop = asyncio.get_event_loop()

        def wrap_run_sniff():
            interface = self.config.interface
            self._sniffer = pcap.pcap(
                name=interface,
                snaplen=2048,
                promisc=True,
                immediate=True,
                timeout_ms=50,
            )

            # We only want to receive incoming packets
            self._sniffer.setdirection(pcap.PCAP_D_IN)

            _LOGGER.info(
                "Initialized pcap sniffer on interface %s (snaplen %s)",
                interface,
                self._sniffer.snaplen,
            )

            try:
                self.run_sniff(self._should_quit)
            except asyncio.TimeoutError:
                _LOGGER.warning("Got asyncio.timeout error during sniffing")

        self._sniffer_task = asyncio.ensure_future(
            loop.run_in_executor(None, wrap_run_sniff)
        )

        return self

    def unwrap_ethernet(self, pkt) -> Union[IP, IP6] | None:
        """Extract an IP or IP6 object from an ethernet frame.

        Returns none on other packets.
        """
        eth = Ethernet(pkt)
        if eth.type == ETH_TYPE_IP:
            self.stats["packets_received_ethernet_v4"] += 1
            return eth.data
        elif eth.type == ETH_TYPE_IP6:
            ip = eth.data
            self.stats["packets_received_ethernet_v6"] += 1
            return ip
        elif eth.type == ETH_TYPE_ARP:
            self.stats["packets_received_arp"] += 1
            # _LOGGER.debug("Received arp, ignoring")
            return None

        self.stats["packets_received_other"] += 1
        _LOGGER.debug("Received unknown ethernet frame with type: %s", eth.type)
        return None

    def unwrap_cooked(self, pkt) -> Union[IP, IP6]:
        """unwrap linux cooked capture.

        this happens due to how ppp interfaces work on linux
        """
        # TODO: should this verify that the data is an ip packet?
        return SLL(pkt).data

    def unwrap_ip(self, pkt) -> Union[IP, IP6] | None:
        try:
            ip = IP(pkt)
            if ip.v == 4 or ip.v == 6:
                return ip
        except Exception:  # Depending on the medium, we may not receive raw IP packets.
            pass

        # wrapping can differ between tun & tap..
        try:
            try:
                ip = self.unwrap_ethernet(pkt)
                self.stats["packets_wrapped_ethernet"] += 1
                return ip
            except:  # noqa: E722
                try:
                    ip = self.unwrap_cooked(pkt)
                    self.stats["packets_cooked"] += 1
                    return ip
                except:  # noqa: E722  # maybe we received an ip packet already, e.g., when using wireguard?
                    pass

            if not isinstance(pkt, IP) and not isinstance(pkt, IP6):
                try:
                    ip = IP(pkt)
                    return ip
                except:  # noqa: E722
                    self.stats["ignored_packets"] += 1
                    return None
        except (NeedData, struct.error) as ex:  # unable to parse the packet..
            _LOGGER.debug("Unable to parse packet: %s", ex)
            self.stats["packets_unable_to_parse"] += 1
            return None
        except Exception as ex:
            _LOGGER.debug("Unable to parse packet: %s", ex)
            self.stats["packets_other_exception"] += 1
            return None

    def run_sniff(self, should_quit):
        """Execute the main packet sniffer loop."""
        last_update = datetime.utcnow()

        for ts, pkt in self._sniffer:
            if last_update + timedelta(seconds=30) < datetime.utcnow():
                last_update = datetime.utcnow()
                _LOGGER.debug("Sniffer still running: %s", self.stats)

            if should_quit.is_set():
                _LOGGER.info("We are not running anymore, let's quit!")
                break

            if pkt is None:
                continue

            self.stats["packets_received"] += 1
            ip = self.unwrap_ip(pkt)

            if ip is None or isinstance(ip, bytes):
                # _LOGGER.warning("Unable to parse the packet: %r", pkt)
                continue

            if ip.v == 6:
                self.stats["packets_received_v6"] += 1
            elif ip.v == 4:
                self.stats["packets_received_v4"] += 1
            else:  # this should never happen
                _LOGGER.warning("Got a packet with invalid ip version: %s", ip.v)
                self.stats["packets_received_invalid_ip_version"] += 1
                continue

            # If we have seen the address already, there is nothing to do
            if ip.src in self.seen_addrs:
                continue

            # We need an ipaddress object to check if the packet came from a private ip address
            try:
                srcip = get_ip(ip.src)
            except Exception as ex:
                _LOGGER.error("Unable to construct IP object: %s", ex)
                self.stats["unable_to_get_srcip"] += 1
                continue

            self.seen_addrs.add(ip.src)
            self.stats["unique_srcips"] += 1

            if srcip.is_global:
                continue

            # The field is called ttl for v4, hlim for v6
            try:
                ttl = ip.ttl  # ipv4
            except AttributeError:
                ttl = ip.hlim  # ipv6

            protocol = ip.p
            protocol_name = PROTOMAP.get(protocol, "unknown %s" % protocol)

            proto_details = ""
            if protocol == socket.IPPROTO_UDP or protocol == socket.IPPROTO_TCP:
                data = ip.data
                proto_details = f"{data.sport=} -> {data.dport=}"
            elif protocol == socket.IPPROTO_ICMP:
                data: ICMP = ip.data
                proto_details = f"{data.type=} {data.code=}"

            _LOGGER.debug(
                "Got new internal: %s [TTL: %s] proto: %s %s",
                srcip,
                ttl,
                protocol_name,
                proto_details,
            )

            self.report(
                Finding(
                    src=str(srcip),
                    ttl=ttl,
                    protocol=protocol,
                    proto_details=proto_details,
                )
            )

            self.stats["unique_internal_ips"] += 1
            self.prober.add_target_address(srcip)

        _LOGGER.info("And we are done, survived out from the sniffing loop!")

    async def quit(self):
        _LOGGER.info("Shutting down pcapsniffer")
        self._should_quit.set()

        # Let other probes to have their chance to run
        await asyncio.sleep(0)

        # A hack to trigger loop quit
        # This is necessary as the loop will only execute when receiving a packet
        await self.execute_command_async(
            f"fping -4 1.1.1.1 -c 1 --interface {self.interface}"
        )

        try:
            shutdown_timeout = 15
            _LOGGER.info(
                "Waiting for sniffer to quit for %s seconds..", shutdown_timeout
            )
            await asyncio.wait_for(self._sniffer_task, shutdown_timeout)
        except Exception as ex:
            await asyncio.sleep(1)
            _LOGGER.error("Sniffer is still running? %s", ex)

        try:
            self._sniffer_task.cancel()
            _LOGGER.debug("Cancelled sniffing task")
        except Exception as ex:
            _LOGGER.error(
                "Unable to cancel the sniff task or close the sniffer: %s",
                ex,
                exc_info=True,
            )
        finally:
            _LOGGER.info("Sniff task has been cancelled")

        captured, dropped, dropped_if = -1, -1, -1
        try:
            captured, dropped, dropped_if = self._sniffer.stats()
        except Exception as ex:
            _LOGGER.error("Unable to get pcap sniffer stats: %s", ex)

        pcap_stats = {
            "pcap_captured": captured,
            "pcap_dropped": dropped,
            "pcap_dropped_if": dropped_if,
        }
        self.stats = {**self.stats, **pcap_stats}
