from __future__ import annotations

import asyncio
import dataclasses
import logging
import traceback
from abc import ABC
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Optional

from async_timeout import timeout

from ..models import Config

_LOGGER = logging.getLogger(__name__)


@dataclasses.dataclass
class Job:
    address: Optional[IPv4Address] = None
    network: Optional[IPv4Network] = None


class Probe(ABC):
    """Baseclass for probes."""

    def __init__(self, *, prober, config: Config, probe_config, **kwargs):
        self.config = config
        self.timeout = self.config.timeout
        self.interface = self.config.interface
        self.prober = prober

        self._inbox = asyncio.Queue()
        self.sentinel = object()
        self.seen_addrs = set()

        self.meta = {}

        self.start_time = None
        self.end_time = None

        self._done = asyncio.Event()

        self._probe_config = probe_config
        self._verbose = self._probe_config.verbose
        self._accepts_input = self._probe_config.accepts_input

        _LOGGER.info(
            "Initialized %s with %s", self.__class__.__name__, self._probe_config
        )

    def submit(self, job):
        """Insert task to the list."""
        self._inbox.put_nowait(job)

    def report(self, finding):
        self.prober.add_finding(finding)

    def quit(self):
        raise NotImplementedError

    async def execute_probe(self):
        _LOGGER.info(f"Running {self}")
        start = datetime.utcnow()
        try:
            self.start_time = start

            async with timeout(delay=self.config.timeout):
                await self.run()
        except asyncio.TimeoutError:
            _LOGGER.warning("Timeouted while executing %s", self)
            self.meta["timeouted"] = True
        except Exception as ex:
            self.success = False
            _LOGGER.error(f"Failed to execute {self}: {ex}", exc_info=True)
            self.stacktrace = traceback.format_exc()
        finally:
            end = datetime.utcnow()
            self.end_time = end

        _LOGGER.info(f"{self} took {end - start}")

        return self

    async def execute_command_async(self, cmd: str, shell: int = True, input=None):
        """Execute command with asyncio."""
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        data = {}
        try:
            async with timeout(delay=self.timeout):
                stdout, stderr = await proc.communicate(input)
                data["stdout"] = stdout.decode()
                data["stderr"] = stderr.decode()

        except asyncio.TimeoutError:
            _LOGGER.warning(
                "Hit the timeout of %s, going to terminate the task", timeout
            )
            try:
                proc.terminate()
                await asyncio.sleep(1)  # give a second before going for sigkill
                if not proc.returncode:
                    proc.kill()

                data["error"] = "timeouted"
            except Exception as ex:
                _LOGGER.error(
                    "Unable to terminate the subprocess: %s", ex, exc_info=True
                )
                data["error"] = "termination-failed"
        finally:
            data["retcode"] = proc.returncode

        full_data = {"cmd": cmd, "data": data}

        return full_data

    async def run(self):
        raise NotImplementedError("Probe should implement run")
