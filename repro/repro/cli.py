import asyncio
import logging

import typer

from .models import Config
from .prober import Prober

app = typer.Typer()


@app.command()
def main(
    interface: str,
    timeout: int = 30,
    debug: bool = False,
):
    """repro -- reactive prober."""
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    conf = {
        "interface": interface,
        "timeout": timeout,
    }
    config = Config(**conf)
    p = Prober(config)
    return asyncio.run(p.probe())
