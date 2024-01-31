import asyncio
import logging
from ipaddress import IPv4Address, IPv4Network
from string import Template

from ..models import CommandProbeConfig
from .probe import Job, Probe

_LOGGER = logging.getLogger(__name__)


MAX_CONCURRENT_COMMANDS = 10


class CommandProbe(Probe):
    """Executes a templated command for input networks."""

    def __init__(self, *, prober, config, probe_config: CommandProbeConfig, **kwargs):
        super().__init__(
            prober=prober, config=config, probe_config=probe_config, **kwargs
        )

        self.active_tasks = list()
        self.throttler = asyncio.Semaphore(MAX_CONCURRENT_COMMANDS)
        self.command_tmpl = Template(probe_config.command)
        self._command = probe_config.command
        for target in probe_config.targets:
            if isinstance(target, IPv4Address):
                self.submit(Job(address=target))
            elif isinstance(target, IPv4Network):
                self.submit(Job(network=target))
            else:
                _LOGGER.warning("Unknown target type: %r", target)

        if not probe_config.accepts_input:
            self.submit(self.sentinel)

    async def execute_command(self, job: Job):
        command = self.command_tmpl.substitute(
            {
                "network": job.network,
                "address": job.address,
                "interface": self.interface,
            }
        )

        _LOGGER.debug("Executing %s", command)
        res = None
        try:
            res = await self.execute_command_async(command, shell=True)
            if self._verbose:
                _LOGGER.debug("Result: %s", res)
        except Exception as ex:
            _LOGGER.error("Got an exception: %s", ex)
        finally:
            self._inbox.task_done()
        return res

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

            if job.network is None and "$network" in self._command:
                _LOGGER.debug("Skipping network-based command for %s", job)
                self._inbox.task_done()
                continue

            if job.address is None and "$address" in self._command:
                _LOGGER.debug("Skipping address-based command for %s", job)
                self._inbox.task_done()
                continue

            async def wrap_command(job):
                """A wrapper to avoid too many concurrent executions at once."""
                async with self.throttler:
                    if self._verbose:
                        _LOGGER.info("Going to execute command for %s", job)
                    result = await self.execute_command(job)
                    return result

            task = asyncio.ensure_future(wrap_command(job))

            self.active_tasks.append(task)

        return self

    async def quit(self):
        self._inbox.put_nowait(self.sentinel)

        try:
            for t in asyncio.as_completed(self.active_tasks):
                res = await t
                if self._verbose:
                    _LOGGER.debug(
                        "[shutdown] Command %s is done: %s",
                        self,
                        res.get("data", -1000),
                    )
        except (asyncio.CancelledError, asyncio.TimeoutError):
            for t in self.active_tasks:
                t.quit()

    def __repr__(self):
        return f"<{self.__class__.__name__}: {self._command}>"
