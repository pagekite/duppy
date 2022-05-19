import asyncio
import base64
import logging
import socket
import struct
import time

from typing import List, Tuple, Union

import async_dns.server
from async_dns.core import CacheNode, DNSMessage, types
from async_dns.server import logger, TCPHandler, DNSDatagramProtocol
from async_dns.server.serve import *
from async_dns.resolver import BaseResolver, ProxyResolver
from async_dns.core.record import (
    rdata_map,
    SOA_RData,
    A_RData,
    AAAA_RData,
    MX_RData,
    SRV_RData,
    TXT_RData,
    CNAME_RData)


# async_dns does not currently support TSIG, so we need this for
# validation.
import dns.tsig
import dns.message
import dns.tsigkeyring


# There will be monkey-patching...
org_server_handle_dns = async_dns.server.handle_dns


class NotImplemented(Exception):
    pass


class DNSUpdateMessage(DNSMessage):
    zd = property(lambda s: s.qd if (s.o == 5) else None)
    pd = property(lambda s: s.an if (s.o == 5) else None)
    up = property(lambda s: s.ns if (s.o == 5) else None)


class Patched_A_RData(A_RData):
    @classmethod
    def load(cls, data: bytes, l: int, size: int):
        if size:
            ip = socket.inet_ntoa(data[l:l + size])
            return l + size, cls(ip)
        else:
            return l + size, cls('')


class NsUpdateResolver(ProxyResolver):
    name = 'NsUpdates'

    def __init__(self, duppy, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.duppy = duppy


def _error(msg, code=2):
    return DNSMessage(qr=1, o=msg.o, qid=msg.qid, aa=0, r=code).pack()


async def validate_hmac(msg, raw_data, cli, keys):
    # Make sure there are some TSIGs, otherwise the validator
    # below will happily parse the request as valid!
    if len([r for r in msg.ar if r.qtype == 250]) < 1:
        logging.debug(
            'Rejected %s: Failed to validate HMAC. No TSIG records found!'
            % cli)
        return False

    zone = msg.zd[0].name.lower()
    reasons = []
    for secret in keys:
        try:
            keyring = dns.tsigkeyring.from_text({
                zone: secret,
                zone+'.': secret})
            valid = dns.message.from_wire(raw_data, keyring)
            return True
        except Exception as e:
            reasons.append(str(e))
    logging.debug(
        'Rejected %s: Failed to validate HMAC. Tried %d key(s): %s'
        % (cli, len(reasons), ', '.join(reasons)))
    return False


async def handle_nsupdate(resolver: BaseResolver, data, addr, protocol):
    '''Handle DNS Update requests'''
    msg = data
    cli = addr[0]
    try:
        duppy = resolver.duppy
        msg = DNSUpdateMessage.parse(data)
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
                yield _error(msg, code=4)  # Not implemented

        elif (len(msg.zd) != 1) or (msg.zd[0].qtype != types.SOA):
            logging.debug('Rejected %s: update Zone section is invalid' % cli)
            yield _error(msg, code=1)  # FORMERR, as per RFC2136

        elif msg.pd:
            logging.debug('Rejected %s: FIXME: prereqs do not work' % cli)
            yield _error(msg, code=4)  # FIXME: Refused, we dislike prereqs

        else:
            zone = msg.zd[0].name.lower()
            keys = await duppy.get_keys(zone)
            if not keys:
                logging.debug('Rejected %s: No update keys found for %s'
                    % (cli, zone))
                yield _error(msg, code=9)  # Updates not enabled for zone

            elif not await validate_hmac(msg, data, cli, keys):
                yield _error(msg, code=5)  # Refused

            else:
                updates = []
                for upd in msg.up:
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
                    elif qtype == 'ANY':
                        data = ''
                    else:
                        raise NotImplemented('Unimplemented: %s' % upd)
                    updates.append((upd, qtype, p1, p2, p3, data))

                for upd, qtype, p1, p2, p3, data in updates:
                    ok = False
                    if qtype == 'ANY' and upd.ttl == 0:
                        args = (upd.name,)
                        logging.debug('%s: delete_all_rrsets%s' % (cli, args))
                        ok = await duppy.delete_all_rrsets(*args)

                    elif upd.ttl == 0 and data == '':
                        args = (upd.name, qtype)
                        logging.debug('%s: delete_rrset%s' % (cli, args))
                        ok = await duppy.delete_rrset(*args)

                    elif upd.ttl == 0:
                        args = (upd.name, qtype, data)
                        logging.debug('%s: delete_from_rrset%s'
                            % (cli, args))
                        ok = await duppy.delete_from_rrset(*args)

                    else:
                        args = (upd.name, qtype, upd.ttl, p1, p2, p3, data)
                        logging.debug('%s: add_to_rrset%s' % (cli, args))
                        ok = await duppy.add_to_rrset(*args)

                    if ok:
                        pass  # FIXME: report success
                    else:
                        yield _error(msg, code=2)  # SERVFAIL

            yield _error(msg, code=2)  # SERVFAIL

    except NotImplemented as e:
        logging.debug('Rejected %s: %s' % (cli, e))
        yield _error(msg, code=4)  # Refused, we don't know how to do this

    except:
        logging.exception('Rejected %s: Internal error' % cli)
        yield _error(msg, code=2)  # SERVFAIL


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
        tasks.append(server.serve_forever())

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

    return start_dns_server(duppy)
