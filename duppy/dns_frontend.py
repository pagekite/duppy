import asyncio
import logging
import struct

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.IN.SRV
import dns.rdtypes.mxbase
import dns.rdtypes.txtbase
import dns.rrset
import dns.tsigkeyring
import dns.update

from . import frontends


class UpdateRejected(Exception):
    pass


def response(msg, code=dns.rcode.SERVFAIL):
    if msg is None:
        msg = dns.message.Message()
    response = dns.message.make_response(msg)
    response.set_rcode(code)
    return response.to_wire()


async def handle_nsupdate(frontend, data, addr):
    '''Handle DNS Update requests'''
    backend = frontend.backend
    dbT = None
    msg = None
    cli = addr[0]
    changes = 0
    try:
        keyring = dns.tsigkeyring.from_text(await backend.get_all_keys())
        msg = dns.message.from_wire(data, keyring=keyring)
        if msg.opcode() == dns.opcode.QUERY:
            msg: dns.update.QueryMessage = msg
            if len(msg.question) != 1:
                logging.info('Only supports single question, got %d' % len(msg.question))
                yield response(msg, code=dns.rcode.NOTIMP)
            elif msg.question[0].rdtype != dns.rdatatype.SOA:
                logging.info('Only supports SOA query, got %d' % dns.rdatatype.to_text(msg.qestion[0].rdtype))
                yield response(msg, code=dns.rcode.NOTIMP)
            else:
                # This happens with nsupdate, if people do not specify a zone.
                # Without the zone, nsupdate sends SOA queries to guess it.
                question = msg.question[0]
                for _, zone in (await backend.get_all_zones()).items():
                    if zone.get('type') and dns.rdatatype.from_text(zone.get('type')) != question.rdtype:
                        continue
                    if await backend.is_in_zone(zone["name"], question.name.to_text(omit_final_dot=True)):
                        res = dns.message.make_response(msg)
                        res.flags |= dns.flags.AA
                        soa_data = dns.rdtypes.ANY.SOA.SOA(
                            question.rdclass,
                            question.rdtype,
                            mname=dns.name.from_text(zone["hostname"]),
                            rname=dns.name.from_text(''),
                            serial=zone.get('serial', 0),
                            refresh=zone.get('ttl', frontend.default_ttl),
                            retry=0,
                            expire=0,
                            minimum=0
                        )
                        rrset = dns.rrset.from_rdata(
                            question.name,
                            soa_data.refresh,
                            soa_data
                        )
                        res.answer.append(rrset)
                        yield res.to_wire()
                        break  # break to avoid going into else clause
                else:
                    yield response(msg, code=dns.rcode.NXDOMAIN)
        elif msg.opcode() == dns.opcode.UPDATE:
            msg: dns.update.UpdateMessage = msg
            zone = msg.zone[0].name
            # section 0 (zone)
            if not msg.had_tsig or not await backend.check_key_in_zone(msg.keyname.to_text(omit_final_dot=True), msg.zone[0].name.to_text(omit_final_dot=True)):
                yield response(msg, code=dns.rcode.REFUSED)
            # section 1 (prerequisite)
            elif msg.prerequisite:
                logging.info('Rejected %s: FIXME: prereqs do not work' % cli)
                yield response(msg, code=dns.rcode.NOTIMP)
            # section 2 (update)
            else:
                # FIXME: This logic overlaps a great deal with the logic
                #        in the HTTP API, we should find a way to unify to
                #        avoid duplicate effort and divergent behavior.

                updates = []
                for upd in msg.update:
                    upd: dns.rrset.RRset = upd
                    if not await backend.is_in_zone(zone.to_text(), upd.name.to_text()):
                        raise UpdateRejected(
                            'Not in zone %s: %s' % (zone.to_text(), upd.name.to_text()))

                    if upd.deleting is None:
                        if upd.ttl < frontend.minimum_ttl:
                            raise UpdateRejected('TTL too low: %d < %d'
                                % (upd.ttl, frontend.minimum_ttl))
                    else:
                        if upd.ttl != 0:
                            raise dns.exception.FormError(f"Invalid TTL {upd.ttl} for deletion update")

                    p1 = p2 = p3 = 0
                    data = ''
                    if upd:
                        if len(upd) != 1:
                            raise UpdateRejected('Unexpected number of data elements: %d != 1' % len(upd.items))
                        data = upd[0]
                        if upd.rdtype == dns.rdatatype.A:
                            data: dns.rdtypes.IN.A.A = data
                            data = data.address
                        elif upd.rdtype == dns.rdatatype.AAAA:
                            data: dns.rdtypes.IN.AAAA.AAAA = data
                            data = data.address
                        elif upd.rdtype == dns.rdatatype.MX:
                            data: dns.rdtypes.mxbase.MXBase = data
                            p1 = data.preference
                            data = data.exchange
                        elif upd.rdtype == dns.rdatatype.SRV:
                            data: dns.rdtypes.IN.SRV.SRV = data
                            p1 = data.priority
                            p2 = data.weight
                            p3 = data.port
                            data = data.target
                        elif upd.rdtype == dns.rdatatype.TXT:
                            data: dns.rdtypes.txtbase.TXTBase = data
                            data = data.strings
                        else:
                            raise UpdateRejected('Unimplemented: %s' % upd)

                    if upd.name == zone and upd.rdtype == dns.rdatatype.ANY:
                        raise UpdateRejected(
                            'Refused to delete entire zone: %s' % zone)

                    # If we get this far, we like this update?
                    updates.append((upd, p1, p2, p3, data))

                zone = msg.zone[0].name.to_text(omit_final_dot=True).lower()
                dbT = await backend.transaction_start(zone)
                ok = 0
                for upd, p1, p2, p3, data in updates:
                    name = upd.name.to_text(omit_final_dot=True).lower()
                    ttl = upd.ttl
                    deleting = dns.rdataclass.to_text(upd.deleting) if upd.deleting else None
                    rdtype = dns.rdatatype.to_text(upd.rdtype)

                    if deleting is None:
                        args = (zone, name, rdtype, ttl, p1, p2, p3, data)
                        logging.info('%s: add_to_rrset%s' % (cli, args))
                        ok = await backend.add_to_rrset(dbT, *args)

                    elif deleting == rdtype == 'ANY':
                        args = (zone, name)
                        logging.info('%s: delete_all_rrsets%s' % (cli, args))
                        ok = await backend.delete_all_rrsets(dbT, *args)

                    elif deleting == 'ANY' and rdtype != 'ANY':
                        args = (zone, name, rdtype)
                        logging.info('%s: delete_rrset%s' % (cli, args))
                        ok = await backend.delete_rrset(dbT, *args)

                    elif deleting == 'NONE':
                        args = (zone, name, rdtype, data)
                        logging.info('%s: delete_from_rrset%s' % (cli, args))
                        ok = await backend.delete_from_rrset(dbT, *args)

                    else:
                        ok = False

                    if ok:
                        changes += 1
                    else:
                        break

                if changes:
                    ok = await backend.notify_changed(dbT, zone) and ok

                if ok:
                    if await backend.transaction_commit(dbT, zone):
                        yield response(msg, code=dns.rcode.NOERROR)
                    else:
                        yield response(msg, code=dns.rcode.SERVFAIL)
                    dbT = None
                else:
                    # Rollback happens finally (below)
                    yield response(msg, code=dns.rcode.SERVFAIL)

    except dns.exception.FormError as e:
        logging.info('Rejected %s: %s' % (cli, e))
        yield response(msg, code=dns.rcode.FORMERR)

    except dns.message.UnknownTSIGKey as e:
        logging.info('Rejected %s: %s' % (cli, e))
        yield response(msg, code=dns.rcode.REFUSED)

    except UpdateRejected as e:
        logging.info('Rejected %s: %s' % (cli, e))
        yield response(msg, code=dns.rcode.NOTIMP)

    except:
        logging.exception('Rejected %s: Internal error' % cli)
        yield response(msg, code=dns.rcode.SERVFAIL)

    finally:
        if dbT is not None:
            await backend.transaction_rollback(dbT, zone, silent=(not changes))


class TCPHandler:
    def __init__(self, frontend):
        self.frontend = frontend

    async def handle_tcp(self, reader, writer):
        addr = writer.transport.get_extra_info('peername')
        while True:
            try:
                size, = struct.unpack('!H', await reader.readexactly(2))
            except asyncio.IncompleteReadError:
                break
            data = await reader.readexactly(size)
            async for result in handle_nsupdate(self.frontend, data, addr):
                bsize = struct.pack('!H', len(result))
                writer.write(bsize)
                writer.write(result)


class DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, frontend):
        super().__init__()
        self.frontend = frontend

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self.handle(data, addr))

    async def handle(self, data, addr):
        async for result in handle_nsupdate(self.frontend, data, addr):
            self.transport.sendto(result, addr)


class DnsFrontend(frontends.Frontend):
    hostname: str
    port: int
    enable_tcp: bool
    enable_udp: bool
    default_ttl: int
    minimum_ttl: int

    def __init__(
            self,
            backend,
            hostname = '0.0.0.0',
            port = 8053,
            enable_tcp = True,
            enable_udp = True,
            default_ttl = 300,
            minimum_ttl = 120,
    ):
        self.hostname = hostname
        self.port = port
        self.enable_tcp = enable_tcp
        self.enable_udp  = enable_udp
        self.default_ttl = default_ttl
        self.minimum_ttl = minimum_ttl
        super().__init__(backend)

    async def get_tasks(self):
        urls = []
        tasks = []
        if self.enable_tcp:
            server = await asyncio.start_server(TCPHandler(self).handle_tcp, self.hostname, self.port)
            for sock in server.sockets:
                host = sock.getsockname()
                urls.append(f"tcp://{host[0]}:{host[1]}")
            tasks.append(asyncio.create_task(server.serve_forever()))

        if self.enable_udp:
            loop = asyncio.get_event_loop()
            transport, _protocol = await loop.create_datagram_endpoint(
                lambda: DatagramProtocol(self),
                local_addr=(self.hostname, self.port))
            host = transport.get_extra_info('sockname')
            urls.append(f"udp://{host[0]}:{host[1]}")

        logging.info('====================')
        for url in urls:
            logging.info('%s', url)
        logging.info('====================')

        logging.info('Servers started')
        return tasks
