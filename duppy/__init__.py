import asyncio
import logging
import typing

from .backends import Backend, SQLBackend
from .frontends import Frontend
from .dns_frontend import DnsFrontend
from .http_frontend import HttpFrontend


class Server:
    """
    This is the main duppy Server class. You are expected to subclass
    this to adapt the server to your local setup.
    """

    def __init__(self, frontends: typing.Iterable[Frontend], backend: Backend, log_level: int = logging.INFO):
        self.frontends = frontends
        self.backend = backend
        self.log_level = log_level

    async def startup_tasks(self):
        """
        Subclasses can override this to perform tasks after the event loop
        has started (so async works), but before the DNS and HTTP servers
        have started running.
        """
        pass

    async def main(self):
        """
        Main async task: runs `self.startup_tasks()`, configures and
        launches the servers, and awaits their completion (they probably
        run forever).
        """
        await self.startup_tasks()

        tasks = []
        for frontend in self.frontends:
            tasks.extend(await frontend.get_tasks())
        await asyncio.wait(tasks)

    def run(self):
        """
        Starts the asyncio loop, running the duppy.Server.main() task.
        """
        logging.basicConfig(level=self.log_level)
        loop = asyncio.get_event_loop()
        loop.create_task(self.main())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
