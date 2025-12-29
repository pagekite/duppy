import asyncio
import logging

from . import backends


class Server:
    """
    This is the main duppy Server class. You are expected to subclass
    this to adapt the server to your local setup.
    """

    # App settings, defaults
    listen_on    = '0.0.0.0'
    http_port    = 5380
    http_prefix  = '/dnsup'
    http_welcome = True
    http_updates = True
    http_simple  = True
    rfc2136_port = 8053
    rfc2136_tcp  = True
    rfc2136_udp  = True
    log_level    = logging.INFO
    minimum_ttl  = 120
    def_ddns_ttl = 300

    def __init__(self, backend: backends.Backend):
        self.backend = backend

    async def startup_tasks(self):
        """
        Subclasses can override this to perform tasks after the event loop
        has started (so async works), but before the DNS and HTTP servers
        have started running.
        """
        pass

    async def get_dns_server_tasks(self):
        """
        Subclasses can override this to return their own list of DNS
        server tasks.
        """
        from . import dns_updates
        return await dns_updates.AsyncDnsUpdateServer(self)

    async def get_http_server_tasks(self):
        """
        Subclasses can override this to return their own list of HTTP
        server tasks.
        """
        from . import http_updates
        return [asyncio.create_task(await http_updates.AsyncHttpApiServer(self).run())]

    async def main(self):
        """
        Main async task: runs `self.startup_tasks()`, configures and
        launches the servers, and awaits their completion (they probably
        run forever).
        """
        await self.startup_tasks()

        tasks = []
        if self.rfc2136_port:
            tasks.extend(await self.get_dns_server_tasks())
        if self.http_port:
            tasks.extend(await self.get_http_server_tasks())

        logging.debug('%s' % tasks)
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
