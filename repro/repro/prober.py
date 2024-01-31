import asyncio
import logging
from datetime import datetime
from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from itertools import groupby

from repro import (
    CommandProbe,
    CommandProbeConfig,
    Config,
    Finding,
    Job,
    Logger,
    PCAPSniffer,
    Probe,
    ProbeConfig,
)

from .models import Report


@lru_cache(maxsize=500)
def get_supernet(x, prefix=24) -> IPv4Network | None:
    """Returns the supernet for a given IP address."""
    try:
        net = ip_network(x)
        if net.version == 6:  # cannot expand v6
            return None

        return net.supernet(new_prefix=prefix)
    except:  # noqa: E722
        _LOGGER.warning(f"Unable to get supernet for {x}")
        return None


_LOGGER = logging.getLogger(__name__)


class Prober:
    """Run probes on an instance."""

    def __init__(self, config: Config):
        self._config = config
        self.interface = config.interface

        self._probes: list[Probe] = []
        self._checked_targets: set[IPv4Address] = set()

        self._findings: list[Finding] = []

        _LOGGER.info(f"Initialized with {config}")

    async def execute_probe(self, probe: Probe):
        try:
            await probe.execute_probe()

        except asyncio.CancelledError:
            _LOGGER.error("%s got cancelled, requesting shutdown", probe)
            try:
                await probe.quit()
            except Exception:
                _LOGGER.error("Unable to cancel %s", probe)

    async def probe(self):
        start_time = datetime.utcnow()
        meta = {"start_time": start_time}

        sniffer = PCAPSniffer(
            prober=self,
            config=self._config,
            probe_config=ProbeConfig(accepts_input=True),
        )

        MTR_TARGETS = [
            "8.8.8.8",  # Google DNS
            "1.1.1.1",  # Cloudflare DNS
            "192.168.0.1",  # 192.168/16 prefix
            "192.168.255.254",  # 192.168/16 prefix
            "10.0.0.1",  # 10/8 prefix
            "10.255.255.254",  # 10/8 prefix
            "172.16.0.1",  # 172.16/12 prefix
            "172.31.255.254",  # 172.16/12 prefix
            "169.254.169.254",  # cloudprovider meta
            "100.64.0.1",  # 100.64.0.0/10 CGNAT
            "100.127.255.254",  # 100.64.0.0/10 CGNAT
        ]

        mtr = CommandProbe(
            prober=self,
            config=self._config,
            probe_config=CommandProbeConfig(
                command="mtr --json $address --report-cycles 1 --no-dns --interface $interface",
                verbose=True,
                accepts_input=False,
                targets=MTR_TARGETS,
            ),
        )
        self._probes.append(mtr)

        FPING_TARGETS = [
            "192.168.0.0/24",
            "172.16.0.0/24",
            "10.0.0.0/24",
            "169.254.169.0/24",  # link-local
            "100.64.0.0/24",  # CGNAT
        ]

        fping = CommandProbe(
            prober=self,
            config=self._config,
            probe_config=CommandProbeConfig(
                command="fping --alive --quiet --generate $network --iface $interface",
                verbose=True,
                accepts_input=True,
                targets=FPING_TARGETS,
            ),
        )
        self._probes.append(fping)

        logger = Logger(
            prober=self,
            config=self._config,
            probe_config=ProbeConfig(accepts_input=True),
        )
        self._probes.append(logger)

        persistent_probes = [logger, sniffer]
        persistent_probes_futs = [
            asyncio.ensure_future(self.execute_probe(p)) for p in persistent_probes
        ]

        probes_fut = [
            asyncio.ensure_future(self.execute_probe(p)) for p in self._probes
        ]

        await self.wait_to_finish(probes_fut)
        _LOGGER.debug("Probing finished, requesting shutdown for persistent probes")
        for p in persistent_probes:
            await p.quit()

        await self.wait_to_finish(persistent_probes_futs)

        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        meta["end_time"] = end_time
        meta["duration"] = duration

        networks = 0
        hosts = 0
        sorted_summary = sorted(self._findings, key=lambda x: x.src)
        summary_str = "== Summary of findings =="
        for network, findings in groupby(sorted_summary, lambda x: get_supernet(x.src)):
            networks += 1
            findings = list(findings)
            summary_str += f"# {network} ({len(findings)}):\n"
            for finding in sorted(findings, key=lambda x: x.ttl):
                hosts += 1
                summary_str += f"\t{finding}\n"

        meta["hosts"] = hosts
        meta["networks"] = networks

        out = Report(findings=self._findings, meta=meta)
        print(out.model_dump_json(indent=2))

        _LOGGER.info(summary_str)
        _LOGGER.info("Probing took %s", duration)
        _LOGGER.info(f"Total: {hosts} hosts in {networks} networks.")

    async def wait_to_finish(self, probes):
        """Wait for tasks to finish and cancel remaining ones if not finished in time."""
        timeout = self._config.timeout
        finished, pending = await asyncio.wait(probes, timeout=timeout)

        for pend in pending:
            _LOGGER.warning("Canceling still pending task: %s", pend)
            pend.cancel()

        try:
            finished_canceled = await asyncio.gather(*pending, return_exceptions=True)
            _LOGGER.debug("Finish pending: %s", finished_canceled)
        except asyncio.TimeoutError:
            _LOGGER.error("Got timeout while waiting canceleds to finish")

    def add_target_address(self, addr: IPv4Address):
        if addr in self._checked_targets:
            return

        if addr.is_global:
            _LOGGER.warning("Got an unexpected global address")
            return

        if addr.version == 6:
            _LOGGER.warning("Got v6 packet, ignoring: %s", addr)
            return

        self._checked_targets.add(addr)

        for probe in self._probes:
            if probe._accepts_input:
                probe.submit(Job(address=addr))

        self._expand_and_add_neighboring_subnets(addr)

    def add_target_network(self, snet):
        # We may have already seen the neighboring network
        if snet in self._checked_targets:
            return

        # Check if our network is a subnet of any of the checked networks.
        for checked in self._checked_targets:
            # Skip individual addresses
            if isinstance(checked, IPv4Address):
                continue
            if snet.subnet_of(checked):
                return

        self._checked_targets.add(snet)

        _LOGGER.info("Added new subnet: %s", snet)

        for probe in self._probes:
            if probe._accepts_input:
                probe.submit(Job(network=snet))

    def add_finding(self, finding: Finding):
        self._findings.append(finding)

    def _expand_and_add_neighboring_subnets(self, addr):
        """This expands the given address to its network and adds their neighbors to the list of networks to check."""
        ip_addr = ip_address(addr)
        if ip_addr.version == 6:
            return

        for addr in [ip_addr, ip_addr + 255, ip_addr - 255]:
            snet = get_supernet(addr)
            # Ignore global networks
            if snet.is_global:
                continue

            self.add_target_network(snet)
