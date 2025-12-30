import asyncio
import base64
import logging

import dns.name

from aiohttp import web

from . import frontends
from . import records


class HttpFrontend(frontends.Frontend):
    hostname: str
    port: int
    http_prefix: str
    default_ttl: int
    minimum_ttl: int
    http_welcome: bool
    http_updates: bool
    http_simple: bool

    def __init__(
            self,
            backend,
            hostname = '0.0.0.0',
            port = 5380,
            prefix = '/dnsup',
            default_ttl = 300,
            minimum_ttl = 120,
            welcome = True,
            updates = True,
            simple = True,
    ):
        self.hostname = hostname
        self.port = port
        self.http_prefix  = prefix
        self.default_ttl = default_ttl
        self.minimum_ttl = minimum_ttl
        self.http_welcome = welcome
        self.http_updates = updates
        self.http_simple  = simple

        self.app = None
        self.site = None
        self.runner = None

        super().__init__(backend)

    def _path_update(self):
        return self.http_prefix + '/v1/update'

    def _path_simple(self):
        return self.http_prefix + '/v1/simple'

    async def welcome_handler(self, request):
        """
        This handler generates a helpful, human-readable summary of
        the Duppy server configuration: what is enabled, URL paths,
        ports, links to documentation.

        This handler is configured as the root page of the built-in
        website/webapp.

        Set `duppy.Server.http_welcome = False` to disable.
        """
        dns_port = self.duppy.rfc2136_port
        if 'md' in request.query:
            return web.Response(content_type='text/plain', text="""\
*This is an auto-generated snapshot of Duppy's welcome page. Do not edit
this directly, and please take the IP addresses with a grain of salt!*

# Dynamic DNS update service

This is a [duppy](https://github.com/pagekite/duppy/) server, for
[dynamically updating DNS records](https://en.wikipedia.org/wiki/Dynamic_DNS).

Check your provider's documentation, or the
[duppy Wiki](https://github.com/pagekite/duppy/wiki) for more information.

You will need to obtain an access token / secret key from your provider
before you can make use of this service.</a>.

------------------------------------------------------------------------------
%s""" % ('\n\n---------\n\n'.join(self._documentation(request, md=True))))
        else:
            return web.Response(content_type='text/html', text="""\
<html><head>
  <title>duppy: dynamic DNS update service</title>
  <style type='text/css'>
    .c {max-width: 50em; margin: 0 auto; font: 14px monospace;}
    table {margin-left: 1em; border: 0; font-size: 12px;}
    td {padding: 0 1em;}
    hr {margin: 2.5em 0 0.5em 0;}
    p, table, pre {margin-left: 1em;}
  </style>
</head><body><div class=c>
  <h1>Dynamic DNS Update Service</h1>
  <p>
    This is a <a href="https://github.com/pagekite/duppy/">duppy</a> server,
    for <a href="https://en.wikipedia.org/wiki/Dynamic_DNS">dynamically
    updating DNS records</a>.
  </p>
  <p>
    Check your provider's documentation, or the
    <a href="https://github.com/pagekite/duppy/wiki">the duppy Wiki</a> for
    more information.
  </p>
  <p>
    You will need to obtain an access token / secret key
    from your provider before you can make use of this service.</a>.
  </p>
  <hr>
%s</div></body></html>""" % ('<hr>'.join(self._documentation(request))))

    def _documentation(self, request, md=False):
        def fmt1(a, txt):
            h2, body  = txt.strip().replace('\n        ', '\n').split('\n', 1)
            body = body.replace(
               '/PREFIX', self.http_prefix).replace(
               'SERVER/', request.headers.get('Host', 'SERVER') + '/')
            return h2, body

        def fmt_md(a, txt):
            h2, body = fmt1(a, txt)
            return '\n<a name="%s"></a>\n\n## %s\n\n%s\n' % (a, h2, body)
        def fmt_html(a, txt):
            h2, body = fmt1(a, txt)
            return '<a name="%s"></a>\n<h2>%s</h2>\n<pre>%s</pre>\n' % (a, h2, body)

        f = fmt_md if md else fmt_html
        if self.http_simple:
            yield f('simple', self.simple_handler.__doc__)
        if self.http_updates:
            yield f('update', self.update_handler.__doc__)

    async def _do_updates(self, cli, zone, updates):
        try:
            zone = dns.name.from_text(zone)
            if (not isinstance(updates, list)
                    or len(updates) < 1
                    or not isinstance(updates[0], dict)):
                raise ValueError('Need a list of updates')
            rrset_updates = [records.rrset_from_json(update) for update in updates]
            await records.validate(zone, rrset_updates, self.backend, self.minimum_ttl)

            await self.backend.update(cli, zone, rrset_updates)
            return (200, 'OK', updates)
        except (KeyError, ValueError) as e:
            return (400, 'Bad request', {'error': str(e)})

    async def update_handler(self, request):
        """
        HTTP API updates:

            POST https://SERVER/PREFIX/v1/update

        The posted data must be JSON, looking something like this:

            {
                "zone": "example.org",
                "key": "+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U=",
                "updates": [
                    {
                        "dns_name": "example.org",
                        "op": "delete",
                        "type": "MX"
                    },
                    {
                        "dns_name": "example.org",
                        "op": "add",
                        "type": "MX",
                        "priority": 10,
                        "data": "mail.example.org"
                    },
                        ...
                ]
            }


        Supported ops are `delete` and `add`. The most common record
        types (A, AAAA, CNAME, MX, SRV, TXT) are supported. There can be
        as many update operations as you need, but all must apply to DNS
        names within the same zone.

        MX additions require the extra paramter `priority`, SRV requires
        `priority`, `weight` and `port`, in addition to the common `data`.

        When deleting, adding `type` and `data` can be used to narrow
        the scope of the deletion.

        The secret key (auth token) can alternately be provided as a
        Bearer token in the HTTP Authorization header, or as a
        query-string argument named `key`.

        FIXME: Discuss returned values

        Set `duppy.Server.http_updates = False` to disable.
        """
        cli = request.remote
        zone = None
        try:
            data = await request.json()
            zone = data.get('zone')

            keys = await self.backend.get_keys(zone)
            if not keys:
                logging.info('Rejected %s: No update keys found for %s'
                    % (cli, zone))
                raise PermissionError('DNS updates unavailable for %s' % zone)

            auth = data.get('key',
                request.query.get('key',
                request.headers.get('Authorization', '')))
            if auth.lower().startswith('bearer '):
                auth = auth.split(' ', 1)[1].strip()
            else:
                auth = auth.replace(' ', '+').strip()  # Escaping is hard, yo
            if not auth or auth not in keys.values():
                logging.info('Rejected %s: No valid keys provided for %s'
                    % (cli, zone))
                raise PermissionError('Invalid DNS update key for %s' % zone)

            c, m, j = await self._do_updates(cli, zone, data.get('updates'))
            resp = web.json_response(j)
            resp.set_status(c, m)

        except PermissionError as e:
            resp = web.json_response({'error': str(e)})
            resp.set_status(403, 'Access denied')
        except (KeyError, ValueError) as e:
            resp = web.json_response({'error': str(e)})
            resp.set_status(400, 'Bad request')
        except:
            resp = web.json_response({'error': True})
            resp.set_status(500, 'Internal error')

        return resp

    async def simple_handler(self, request):
        """
        Simple updates:

            GET https://u:p@SERVER/PREFIX/v1/simple?hostname=...&myip=...

        The username should be the zone, and the password is the
        secret key (auth token). These should be sent using HTTP Basic
        authentication.

        Both hostname and myip can have multiple (comma separated)
        values. IPv4 and IPv6 addresses are both supported.

        FIXME: Discuss returned values

        Responses are appropriate HTTP status codes and a plain/text
        summary.

        Set `duppy.Server.http_simple = False` to disable.
        """
        cli = request.remote
        zone = None
        try:
            auth = request.headers.get('Authorization', '')
            if not auth.lower().startswith('basic '):
                raise PermissionError('Please authenticate with zone and key')
            auth = str(base64.b64decode(auth.split(' ', 1)[1]), 'utf-8')
            zone, auth = auth.split(':', 1)

            keys = await self.backend.get_keys(zone)
            if not keys:
                logging.info('Rejected %s: No update keys found for %s'
                    % (cli, zone))
                raise PermissionError('DNS updates unavailable for %s' % zone)

            if not auth or auth not in keys.values():
                logging.info('Rejected %s: No valid keys provided for %s'
                    % (cli, zone))
                raise PermissionError('Invalid DNS update key for %s' % zone)

            myips = request.query.get('myip', 'missing').split(',')
            myipv6 = request.query.get('myipv6', '').split(',')
            if not (myipv6 and myipv6[0]):
                myipv6 = [ip for ip in myips if ':' in ip]
            myips = [ip for ip in myips if (':' not in ip) and ip]
            hostnames = request.query.get('hostname', '').split(',')
            ttl = request.query.get('ttl', self.default_ttl)
            if request.query.get('offline'):
                myips = myipv6 = []

            updates = []
            for dns_name in hostnames:
                for rtype, iplist in (('A', myips), ('AAAA', myipv6)):
                    for ip in iplist:
                        updates.append({
                            'op': 'add',
                            'dns_name': dns_name,
                            'ttl': ttl,
                            'type': rtype,
                            'data': ip})
                    if not iplist:
                        updates.append({
                            'op': 'delete',
                            'dns_name': dns_name,
                            'type': rtype})

            print('%s' % updates)
            c, m, j = await self._do_updates(cli, zone, updates)

        except PermissionError as e:
            c, m, j = 403, 'Access denied', {'error': str(e)}
        except:
            c, m, j = 500, 'Internal error', {'error': True}

        if c == 200:
            hostnames = ['-']
            responses = []
            for status, op in j:
                if status == 'ok' and op['op'] == 'add':
                    if op['dns_name'] != hostnames[-1]:
                        hostnames.append(op['dns_name'])
                        responses.append('good %s' % op['data'])
                    else:
                        responses[-1] += ',%s' % op['data']
            resp = web.Response(text='\n'.join(responses) + '\n')
        elif c == 403:
            resp = web.Response(text='badauth\n')
        else:
            # FIXME: This is dumb, it conflates both invalid input and
            #        errors on our side. The HTTP status code differentiates.
            resp = web.Response(text='911\n')
        resp.set_status(c, m)

        return resp

    async def run(self):
        """
        Configure the server and return a ready-to-run asyncio task.

        Sets `self.app`, `self.runner` and `self.site` as one might expect
        for an aiohttp server, which subclasses could make use of.
        """
        routes = []
        if self.http_welcome:
            routes.append(web.get('/', self.welcome_handler))
        if self.http_simple:
            routes.append(
                web.get(self._path_simple(), self.simple_handler))
        if self.http_updates:
            routes.append(
                web.post(self._path_update(), self.update_handler))

        self.app = web.Application()
        self.app.add_routes(routes)
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        self.site = web.TCPSite(
            self.runner, self.hostname, self.port)
        logging.debug('Starting HttpApiServer on %s:%s'
            % (self.hostname, self.port))

        return self.site.start()

    async def get_tasks(self):
        return [asyncio.create_task(await self.run())]
