import logging
from aiohttp import web


class AsyncHttpApiServer:
    def __init__(self, duppy):
        self.duppy = duppy

    async def root_handler(self, request):
        return web.Response(content_type='text/html', text="""\
<html><head>
  <title>duppy: dynamic DNS update service</title>
  <style type='text/css'>.c {max-width: 40em; margin: 0 auto;}</style>
</head><body><div class=c>
  <h1>Dynamic DNS Update Service</h1>
  <p>
    This is a <a href="https://github.com/pagekite/duppy/">duppy</a> server,
    for <a href="https://en.wikipedia.org/wiki/Dynamic_DNS">dynamically
    updating DNS records</a>.
  </p>
  <ul>
    <li><a href="https://github.com/pagekite/duppy/wiki/HTTP_API">HTTP API</a>
        updates are: <b>enabled</b>
    <li><a href="https://datatracker.ietf.org/doc/html/rfc2136">RFC2136</a>
        updates are: <b>%s</b>
  </ul>
  <p>
    Check your provider's documentation, or the
    <a href="https://github.com/pagekite/duppy/wiki">the duppy Wiki</a> for
    more information. You will need to obtain an access token / secret key
    from your provider before you can make use of this service.</a>.
  </p>
</div></body></html>""" % (
            'enabled' if self.duppy.rfc2136_port else 'disabled'))

    async def run(self):
        app = web.Application()
        app.add_routes([
            web.get('/', self.root_handler)])

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, self.duppy.listen_on, self.duppy.http_port)
        logging.debug('Starting HttpApiServer on %s:%s'
            % (self.duppy.listen_on, self.duppy.http_port))

        return site.start()
