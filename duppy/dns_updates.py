import asyncio
import base64
import logging
import struct
import time

from typing import List, Tuple, Union

import async_dns.server
from async_dns.core.record import DNSMessage, CNAME_RData, NS_RData, types
from async_dns.server import logger, TCPHandler, DNSDatagramProtocol
from async_dns.server.serve import *
from async_dns.resolver import BaseResolver

# async_dns does not currently support TSIG, so we need this for
# validation.
import dns.tsig
import dns.message
import dns.tsigkeyring


TEST_KEYS = {
    'example.com' : [('hmac-sha256', '+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U=')],
    'example.org' : [('hmac-sha256', '+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U=')]
}


class DNSUpdateMessage(DNSMessage):
    zd = property(lambda s: s.qd if (s.o == 5) else None)
    pd = property(lambda s: s.an if (s.o == 5) else None)
    up = property(lambda s: s.ns if (s.o == 5) else None)


class NsUpdateResolver(BaseResolver):
    name = 'NsUpdates'


def _error(msg, code=2):
    return DNSMessage(qr=1, o=msg.o, qid=msg.qid, aa=0, r=code).pack()


def our_zone(msg):
    zone = msg.zd[0].name.lower()
    if zone in TEST_KEYS:
        return True
    else:
        logging.debug('Zone %s unavailable for updates' % zone)
        return False


def validate_hmac(msg, raw_data):
    # Make sure there are some TSIGs, otherwise the validator
    # below will happily parse the request as valid!
    if len([r for r in msg.ar if r.qtype == 250]) < 1:
        logging.debug('Failed to validate HMAC. No TSIG records found!')
        return False

    zone = msg.zd[0].name.lower()
    reasons = []
    for algo, secret in TEST_KEYS.get(zone, []):
        try:
            keyring = dns.tsigkeyring.from_text({zone: secret})
            valid = dns.message.from_wire(raw_data, keyring)
            return True
        except Exception as e:
            reasons.append(str(e))
    logging.debug(
        'Failed to validate HMAC. Tried %d key(s): %s'
        % (len(reasons), ', '.join(reasons)))
    return False


async def handle_nsupdate(resolver: BaseResolver, data, addr, protocol):
    '''Handle DNS Update requests'''
    try:
        msg = DNSUpdateMessage.parse(data)
        if msg.zd is None:
            # FIXME: This is a problem for nsupdate if people do not
            #        specify a zone - without the zone, nsupdate tries to
            #        send SOA queries to figure out what zone to use. We
            #        are rejecting these, but should perhaps forward?
            #
            logging.debug('Rejected non-update query')
            yield _error(msg, code=4)  # Not implemented

        elif (len(msg.zd) != 1) or (msg.zd[0].qtype != types.SOA):
            logging.debug('Update Zone section is invalid')
            yield _error(msg, code=1)  # FORMERR, as per RFC2136

        elif msg.pd:
            logging.debug('FIXME: Update has prereqs, bailing out.')
            yield _error(msg, code=4)  # FIXME: Refused, we dislike prereqs

        elif not our_zone(msg):
            yield _error(msg, code=9)  # Not our zone, or updates not enabled

        elif not validate_hmac(msg, data):
            yield _error(msg, code=5)  # Refused

        else:
            for update in msg.up:
                logging.debug('Want update: %s' % update)

            # TODO3: Parse what is being asked of us!

# INFO:async_dns.core:Q:
#     <DNSMessage type=0 qid=13397 r=0
#         QD=[<Record type=request qtype=SOA name=example.com>]
#         AN=[]
#         NS=[<Record type=response qtype=A name=www1.example.com ttl=300 data=<a: 1.2.3.4>>,
#             <Record type=response qtype=TXT name=www2.example.com ttl=300 data=<txt: hello>>]
#         AR=[<Record type=response qtype=250 name=ddns-key ttl=0 data=<250: (250, b'\x0bhmac-sha256\x00\x00\x00b\x84\xe7x\x01,\x00 \xfe\xcd&\x11\xe9\x81z\xbe\x9d\x86\xb2\xda\xc7\xfd\xfa\xe3\t\xd3\xbf\x08\xe6\xdb\xa8\xd1\xae_\xef\x9b\xc5\xa1\xdd\xfb4U\x00\x00\x00\x00')>>]>

            yield _error(msg, code=2)  # SERVFAIL

    except:
        logging.exception('Failed to handle %s' % msg)
        yield _error(msg, code=2)  # SERVFAIL

    return
    for question in msg.qd:
        res = None
        try:
            error = None
            res, cached = await resolver.query(question.name, question.qtype)
        except Exception as e:
            import traceback
            logger.debug('[server_handle][%s][%s] %s',
                         types.get_name(question.qtype), question.name,
                         traceback.format_exc())
            error = str(e)
            res, cached = None, None

        if res is not None:
            res.qid = msg.qid
            data = res.pack(
                size_limit=512 if protocol == 'udp' else None)  # rfc2181
            len_data = len(data)
            yield data
            res_code = res.r
        else:
            len_data = 0
            res_code = -1


async def start_dns_server(bind=':53',
                           enable_tcp=True,
                           enable_udp=True):
    '''Start a DNS server.'''

    resolver = NsUpdateResolver()

    loop = asyncio.get_event_loop()
    host = Host(bind)
    urls = []
    tasks = []
    if enable_tcp:
        server = await start_server(TCPHandler(resolver).handle_tcp, bind)
        urls.extend(get_server_hosts([server], 'tcp:'))
        tasks.append(server.serve_forever())

    if enable_udp:
        hostname = host.hostname or '::'  # '::' includes both IPv4 and IPv6
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: DNSDatagramProtocol(resolver),
            local_addr=(hostname, host.port or 53))
        urls.append(
            get_url_items([transport.get_extra_info('sockname')], 'udp:'))

    for line in repr_urls(urls):
        logger.info('%s', line)

    logger.info('%s started', resolver.name)
    return tasks


def AsyncDnsUpdateServer(duppy):
    async_dns.server.handle_dns = handle_nsupdate
    return start_dns_server(
        bind='%s:%s' % (duppy.listen_on, duppy.rfc2136_port))
