import json.decoder
import logging
import re

import dns.ipv4
import dns.ipv6
import dns.ttl

from aiohttp import web



class AsyncHttpApiServer:
    def __init__(self, duppy):
        self.duppy = duppy
        self._rtype_to_add_op = {
            'A':     self._add_ARecord,
            'AAAA':  self._add_AAAARecord,
            'CNAME': self._add_CNAMERecord,
            'MX':    self._add_MXRecord,
            'SRV':   self._add_SRVRecord,
            'TXT':   self._add_TXTRecord}

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

    def _common_args(self, zone, obj,
            require=('dns_name', 'data', 'ttl', 'type'),
            allowed=[]):

        for p in obj:
            if not (p in require or p in allowed or p in ('op', 'zone')):
                raise ValueError('Unrecognized parameter: %s' % p)
        for p in require:
            if not obj.get(p):
                raise ValueError('Missing reqired parameter: %s' % p)

        dns_name = obj['dns_name']
        if dns_name != zone and not dns_name.endswith('.'+zone):
            raise ValueError('Not in zone %s: %s' % (zone, dns_name))

        if 'ttl' not in require and 'ttl' not in obj:
            ttl = None
        else:
            try:
                ttl = dns.ttl.from_text('%s' % obj['ttl'])
            except (KeyError, ValueError, dns.ttl.BadTTL):
                raise ValueError('TTL missing or invalid')
            if ttl < self.duppy.minimum_ttl:
                raise ValueError('TTL is too low, %s < %s'
                    % (ttl, self.duppy.minimum_ttl))

        return dns_name, obj.get('type'), ttl, obj.get('data')

    def _mk_add_op(self, zone, dns_name, rtype, ttl, i1, i2, i3, data):
        def _op(cli, dbT):
            args = (zone, dns_name, rtype, ttl, i1, i2, i3, data)
            logging.info('%s: add_to_rrset%s' % (cli, args))
            # FIXME: We need to delete_rrset or delete_from_rrset
            #        to ensure we do not end up with duplicate
            #        records; which depends on the rtype.
            return self.duppy.add_to_rrset(dbT, *args)
        return _op

    def _mk_delete_op(self, zone, obj):
        dns_name, rtype, ttl, data = self._common_args(zone, obj,
            require=('dns_name',),
            allowed=('type', 'ttl', 'data'))

        if rtype is None and dns_name == zone:
            raise ValueError('Refused to delete entire zone: %s' % zone)

        def _op(cli, dbT):
            args = [zone, dns_name, rtype, data]
            if rtype is None:
                logging.info('%s: delete_all_rrsets%s' % (cli, args[:2]))
                return self.duppy.delete_all_rrsets(dbT, *args[:2])
            elif data is None:
                logging.info('%s: delete_rrset%s' % (cli, args[:3]))
                return self.duppy.delete_rrset(dbT, *args[:3])
            else:
                logging.info('%s: delete_from_rrset%s' % (cli, args[:4]))
                return self.duppy.delete_from_rrset(dbT, *args[:4])
        return _op


    def _add_ARecord(self, zone, obj):
        try:
            dns_name, rtype, ttl, data = self._common_args(zone, obj)
            dns.ipv4.inet_aton(data)
            return self._mk_add_op(
                zone, dns_name, rtype, ttl, None, None, None, data)
        except dns.exception.SyntaxError:
            raise ValueError('Invalid IPv4 address: %s' % data)

    def _add_AAAARecord(self, zone, obj):
        try:
            dns_name, rtype, ttl, data = self._common_args(zone, obj)
            dns_name, ttl, data = self._common_args(zone, obj)
            dns.ipv6.inet_aton(data)
            return self._mk_add_op(
                zone, dns_name, rtype, ttl, None, None, None, data)
        except dns.exception.SyntaxError:
            raise ValueError('Invalid IPv6 address: %s' % data)

    def _add_CNAMERecord(self, zone, obj):
        dns_name, rtype, ttl, data = self._common_args(zone, obj)
        if not re.match(r'^([a-zA-Z0-9_-]+)(\.[a-zA-Z0-9_-]+)*$', data):
            raise ValueError('Invalid CNAME destination: %s' % data)
        return self._mk_add_op(
            zone, dns_name, rtype, ttl, None, None, None, data)

    def _add_SRVRecord(self, zone, obj):
        dns_name, rtype, ttl, data = self._common_args(zone, obj,
            require=('dns_name', 'type', 'ttl',
                     'priority', 'weight', 'port', 'data'))
        try:
            pri = int(obj['priority'])
            weight = int(obj['weight'])
            port = int(obj['port'])
            if pri < 0 or port < 0 or weight < 0:
                raise ValueError()
        except (KeyError, ValueError):
            raise ValueError('Invalid priority, weight or port')
        if not re.match(r'^([a-zA-Z0-9_-]+)(\.[a-zA-Z0-9_-]+\.)*$', data):
            raise ValueError('Invalid SRV destination: %s' % data)
        return self._mk_add_op(
            zone, dns_name, rtype, ttl, pri, weight, port, data)

    def _add_MXRecord(self, zone, obj):
        dns_name, rtype, ttl, data = self._common_args(zone, obj,
            require=('dns_name', 'type', 'ttl', 'priority', 'data'))
        try:
            pri = int(obj['priority'])
            if pri < 1:
                raise ValueError()
        except (KeyError, ValueError):
            raise ValueError('Invalid priority')
        if not re.match(r'^([a-zA-Z0-9_-]+)(\.[a-zA-Z0-9_-]+\.)*$', data):
            raise ValueError('Invalid MX destination: %s' % data)
        return self._mk_add_op(
            zone, dns_name, rtype, ttl, pri, None, None, data)

    def _add_TXTRecord(self, zone, obj):
        dns_name, rtype, ttl, data = self._common_args(zone, obj)
        return self._mk_add_op(
            zone, dns_name, rtype, ttl, None, None, None, data)


    def _updates_to_ops(self, zone, updates):
        ops = []
        for update in updates:
            op = update['op']

            if op == 'delete':
                ops.append((update, self._mk_delete_op(zone, update)))

            elif op == 'add':
                ops.append((
                    update,
                    self._rtype_to_add_op[update['type']](zone, update)))

            else:
                raise ValueError('Unknown update: %s' % words[0])
        return ops

    async def update_handler(self, request):
        dbT = None
        zone = None
        changes = 0
        cli = request.remote
        try:
            data = await request.json()
            key = data.get('key')
            zone = data.get('zone')

            keys = await self.duppy.get_keys(zone)
            if not keys:
                logging.info('Rejected %s: No update keys found for %s'
                    % (cli, zone))
                raise PermissionError('DNS updates unavailable for %s' % zone)

            auth = request.query.get(
                'key', request.headers.get('Authorization', ''))
            if auth.lower().startswith('bearer '):
                auth = auth.split(' ', 1)[1].strip()
            else:
                auth = auth.replace(' ', '+').strip()  # Escaping is hard, yo
            if not auth or auth not in keys:
                logging.info('Rejected %s: No valid keys provided for %s'
                    % (cli, zone))
                raise PermissionError('Invalid DNS update key for %s' % zone)

            updates = data.get('updates')
            if (not isinstance(updates, list)
                    or len(updates) < 1
                    or not isinstance(updates[0], dict)):
                raise ValueError('Need a list of updates')

            ops = self._updates_to_ops(zone, updates)
            dbT = await self.duppy.transaction_start(zone)
            ok = True
            results = []
            for req, op in ops:
                ok = await op(cli, dbT)
                if ok:
                    results.append(['ok', req])
                    changes += 1
                else:
                    logging.error('Failed: %s' % req)
                    break

            if changes:
                ok = await self.duppy.notify_changed(dbT, zone) and ok

            if ok and await self.duppy.transaction_commit(dbT, zone):
                resp = web.json_response(results)
                dbT = None
            else:
                raise Exception('Internal Error')

        except ValueError as e:
            resp = web.json_response({'error': str(e)})
            resp.set_status(400, 'Bad request')
        except PermissionError as e:
            resp = web.json_response({'error': str(e)})
            resp.set_status(403, 'Access denied')
        except json.decoder.JSONDecodeError:
            resp = web.json_response({'error': 'Invalid JSON'})
            resp.set_status(400, 'Bad request')
        except:
            logging.exception('Failed to parse')
            resp = web.json_response({'error': True})
            resp.set_status(500, 'Internal error')
        finally:
            if dbT is not None:
                await self.duppy.transaction_rollback(
                    dbT, zone, silent=(not changes))

        return resp

    async def run(self):
        app = web.Application()
        app.add_routes([
            web.get('/', self.root_handler),
            # FIXME: Add handlers for old fashioned dynamic-DNS IP updates
            web.post('/update_dns', self.update_handler)])

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, self.duppy.listen_on, self.duppy.http_port)
        logging.debug('Starting HttpApiServer on %s:%s'
            % (self.duppy.listen_on, self.duppy.http_port))

        return site.start()
