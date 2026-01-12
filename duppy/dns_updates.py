import asyncio
import logging
import socket

import async_dns.server
from async_dns.core import CacheNode, DNSMessage, types
from async_dns.server import logger, TCPHandler, DNSDatagramProtocol
from async_dns.server.serve import Host, get_server_hosts, get_url_items, repr_urls, start_server
from async_dns.resolver import BaseResolver, ProxyResolver
from async_dns.core.record import rdata_map, A_RData, AAAA_RData


# Sadly, async_dns does not currently support TSIG, so we need this
# for validation and generation of correctly signed replies.
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring


# There will be monkey-patching...
org_server_handle_dns = async_dns.server.handle_dns


class UpdateRejected(Exception):
    pass


class DNSUpdateMessage(DNSMessage):
    zd = property(lambda s: s.qd if (s.o == dns.opcode.UPDATE) else None)
    pd = property(lambda s: s.an if (s.o == dns.opcode.UPDATE) else None)
    up = property(lambda s: s.ns if (s.o == dns.opcode.UPDATE) else None)


class Patched_A_RData(A_RData):
    @classmethod
    def load(cls, data: bytes, l: int, size: int):
        if size:
            ip = socket.inet_ntoa(data[l:l + size])
            return l + size, cls(ip)
        else:
            return l + size, cls('')


class Patched_AAAA_RData(AAAA_RData):
    @classmethod
    def load(cls, data: bytes, l: int, size: int):
        if size:
            ip = socket.inet_ntop(socket.AF_INET6, data[l:l + size])
            return l + size, cls(ip)
        else:
            return l + size, cls('')


class NsUpdateResolver(ProxyResolver):
    name = 'NsUpdates'

    def __init__(self, duppy, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.duppy = duppy


def response(msg, keys, code=dns.rcode.SERVFAIL):
    if isinstance(msg, DNSMessage):
        return DNSMessage(qr=1, o=msg.o, qid=msg.qid, aa=0, r=code).pack()
    elif isinstance(msg, dns.message.Message):
        response = dns.message.make_response(msg)
        response.set_rcode(code)
        return response.to_wire()
    else:
        return DNSMessage(qr=1, qid=0, aa=0, r=code).pack()


async def validate_hmac(msg, raw_data, cli, rargs):
    # Make sure there are some TSIGs, otherwise the validator
    # below will happily parse the request as valid!
    if len([r for r in msg.ar if r.qtype == dns.rdatatype.TSIG]) < 1:
        logging.debug(
            'Rejected %s: Failed to validate HMAC. No TSIG records found!'
            % cli)
        return False

    # Keys come from rargs, due to the hack explained below.
    keys = rargs[1]

    zone = msg.zd[0].name.lower()
    reasons = []
    while keys:
        secret = keys.pop(0)
        try:
            keyring = dns.tsigkeyring.from_text({
                zone: secret,
                zone+'.': secret})
            valid = dns.message.from_wire(raw_data, keyring)

            # So this is weird magic: here we change our response args
            # to include the dns.message.Message and keyring, so we can
            # use dnspython to generate signed replies.
            rargs[0] = valid
            rargs[1] = keyring

            return True
        except Exception as e:
            reasons.append(str(e))

    logging.info(
        'Rejected %s: Failed to validate HMAC. Tried %d key(s): %s'
        % (cli, len(reasons), ', '.join(reasons)))
    return False


async def handle_nsupdate(resolver: BaseResolver, data, addr, protocol):
    '''Handle DNS Update requests'''
    duppy = resolver.duppy
    keys = []
    dbT = None
    msg = data
    cli = addr[0]
    changes = 0
    rargs = [None, keys]
    try:
        msg = DNSUpdateMessage.parse(data)
        rargs = [msg, keys]
        if msg.zd is None:
            # This happens with nsupdate, if people do not specify a zone.
            # Without the zone, nsupdate sends SOA queries to guess it.
            if duppy.upstream_dns:
                logging.debug('Proxying %s: non-update query' % cli)
                async for r in org_server_handle_dns(
                        resolver, data, addr, protocol):
                    yield r
            else:
                logging.debug('Rejected %s: non-update query' % cli)
                yield response(*rargs, code=dns.rcode.NOTIMP)

        elif (len(msg.zd) != 1) or (msg.zd[0].qtype != types.SOA):
            logging.debug('Rejected %s: update Zone section is invalid' % cli)
            yield response(*rargs, code=dns.rcode.FORMERR)

        elif msg.pd:
            logging.info('Rejected %s: FIXME: prereqs do not work' % cli)
            yield response(*rargs, code=dns.rcode.NOTIMP)

        else:
            zone = msg.zd[0].name.lower()
            keys[:] = await duppy.get_keys(zone)
            if not keys:
                logging.info('Rejected %s: No update keys found for %s'
                    % (cli, zone))
                yield response(*rargs, code=dns.rcode.NOTAUTH)

            # Note: Here be magic, validate_hmac will as a side-effect
            #       change rargs so responses from here on get signed.
            elif not await validate_hmac(msg, data, cli, rargs):
                yield response(*rargs, code=dns.rcode.REFUSED)

            else:
                updates = []

                # FIXME: This logic overlaps a great deal with the logic
                #        in the HTTP API, we should find a way to unify to
                #        avoid duplicate effort and divergent behavior.

                for upd in msg.up:
                    qclass = dns.rdataclass.to_text(upd.qclass)

                    if not duppy.is_in_zone(zone, upd.name):
                        raise UpdateRejected(
                            'Not in zone %s: %s' % (zone, upd.name))

                    if (qclass == 'IN') and (upd.ttl < duppy.minimum_ttl):
                        raise UpdateRejected('TTL too low: %d < %d'
                            % (upd.ttl, duppy.minimum_ttl))

                    p1 = p2 = p3 = 0
                    data = upd.data
                    qtype = types.get_name(upd.qtype)
                    if qtype == 'MX':
                        p1 = data.preference
                        data = data.exchange
                    elif qtype == 'SRV':
                        p1 = data.priority
                        p2 = data.weight
                        p3 = data.port
                        data = data.hostname
                    elif qtype in ('A', 'AAAA', 'TXT', 'SRV', 'MX'):
                        data = data.data
                    elif qclass == qtype == 'ANY' and upd.ttl == 0:
                        data = ''
                    else:
                        raise UpdateRejected('Unimplemented: %s' % upd)

                    if upd.name == zone and qtype == 'ANY' and upd.ttl == 0:
                        raise UpdateRejected(
                            'Refused to delete entire zone: %s' % zone)

                    # If we get this far, we like this update?
                    updates.append((upd, qtype, qclass, p1, p2, p3, data))

                dbT = await duppy.transaction_start(zone)
                ok = 0
                for upd, qtype, qclass, p1, p2, p3, data in updates:
                    if qclass == qtype == 'ANY' and upd.ttl == 0:
                        args = (zone, upd.name,)
                        logging.info('%s: delete_all_rrsets%s' % (cli, args))
                        ok = await duppy.delete_all_rrsets(dbT, *args)

                    elif qclass == 'ANY' and upd.ttl == 0 and data == '':
                        args = (zone, upd.name, qtype)
                        logging.info('%s: delete_rrset%s' % (cli, args))
                        ok = await duppy.delete_rrset(dbT, *args)

                    elif qclass == 'NONE' and upd.ttl == 0:
                        args = (zone, upd.name, qtype, data)
                        logging.info('%s: delete_from_rrset%s' % (cli, args))
                        ok = await duppy.delete_from_rrset(dbT, *args)

                    elif qclass == 'IN':
                        args = (zone, upd.name, qtype, upd.ttl, p1, p2, p3, data)
                        logging.info('%s: add_to_rrset%s' % (cli, args))
                        # FIXME: We need to delete_rrset or delete_from_rrset
                        #        to ensure we do not end up with duplicate
                        #        records; which depends on the rtype.
                        ok = await duppy.add_to_rrset(dbT, *args)

                    else:
                        ok = False

                    if ok:
                        changes += 1
                    else:
                        break

                if changes:
                    ok = await duppy.notify_changed(dbT, zone) and ok

                if ok:
                    if await duppy.transaction_commit(dbT, zone):
                        yield response(*rargs, code=dns.rcode.NOERROR)
                    else:
                        yield response(*rargs, code=dns.rcode.SERVFAIL)
                    dbT = None
                else:
                    # Rollback happens finally (below)
                    yield response(*rargs, code=dns.rcode.SERVFAIL)

    except UpdateRejected as e:
        logging.info('Rejected %s: %s' % (cli, e))
        yield response(*rargs, code=dns.rcode.NOTIMP)

    except:
        logging.exception('Rejected %s: Internal error' % cli)
        yield response(*rargs, code=dns.rcode.SERVFAIL)

    finally:
        if dbT is not None:
            await duppy.transaction_rollback(dbT, zone, silent=(not changes))


async def start_dns_server(duppy):
    '''Start a DNS server.'''

    resolver = NsUpdateResolver(duppy, CacheNode(),
        proxies=[duppy.upstream_dns] if duppy.upstream_dns else [])

    bind = '%s:%d' % (duppy.listen_on, duppy.rfc2136_port)
    loop = asyncio.get_event_loop()
    host = Host(bind)
    urls = []
    tasks = []
    if duppy.rfc2136_tcp:
        server = await start_server(TCPHandler(resolver).handle_tcp, bind)
        urls.extend(get_server_hosts([server], 'tcp:'))
        tasks.append(asyncio.create_task(server.serve_forever()))

    if duppy.rfc2136_udp:
        hostname = host.hostname or '::'  # '::' includes both IPv4 and IPv6
        portno = int(host.port or duppy.rfc2136_port)
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: DNSDatagramProtocol(resolver),
            local_addr=(hostname, portno))
        urls.append(
            get_url_items([transport.get_extra_info('sockname')], 'udp:'))

    for line in repr_urls(urls):
        logger.info('%s', line)

    logger.info('%s started', resolver.name)
    return tasks


def AsyncDnsUpdateServer(duppy):
    # FIXME: monkey-patch async_dns instead of duplicating lots of code.
    async_dns.server.handle_dns = handle_nsupdate
    rdata_map[Patched_A_RData.rtype] = Patched_A_RData
    rdata_map[Patched_AAAA_RData.rtype] = Patched_AAAA_RData

    return start_dns_server(duppy)
