import asyncio
import logging

from .. import Config
from .probe import Probe

_LOGGER = logging.getLogger(__name__)


class Logger(Probe):
    """Probe to log incoming jobs."""

    def __init__(self, *, prober, config: Config, probe_config, **kwargs):
        super().__init__(
            prober=prober, config=config, probe_config=probe_config, **kwargs
        )

        self._seen_addresses = set()
        self._seen_networks = set()

    async def run(self):
        while True:
            try:
                job = await asyncio.wait_for(self._inbox.get(), 0.05)
                if job == self.sentinel:
                    _LOGGER.info("Got the sentinel, not accepting new jobs")
                    self._inbox.task_done()
                    break
            except asyncio.TimeoutError:
                continue

            if job.network is not None:
                _LOGGER.info("Got network: %s", job.network)
                self._seen_networks.add(job.network)
            if job.address is not None:
                _LOGGER.info("Got address: %s", job.address)
                self._seen_addresses.add(job.address)

            self._inbox.task_done()

    async def quit(self):
        self._inbox.put_nowait(self.sentinel)
