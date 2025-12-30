import asyncio
import logging
import struct

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.tsigkeyring
import dns.update

from . import frontends
from . import records


class UpdateRejected(Exception):
    pass


def response(msg, code=dns.rcode.SERVFAIL):
    if msg is None:
        msg = dns.message.Message()
    response = dns.message.make_response(msg)
    response.set_rcode(code)
    return response.to_wire()


async def handle_nsupdate(frontend, data, addr):
    """Handle DNS Update requests"""
    backend = frontend.backend
    msg = None
    cli = addr[0]
    try:
        keyring = dns.tsigkeyring.from_text(await backend.get_all_keys())
        msg = dns.message.from_wire(data, keyring=keyring)
        if msg.opcode() == dns.opcode.QUERY:
            msg: dns.update.QueryMessage = msg
            if len(msg.question) != 1:
                logging.info("Only supports single question, got %d" % len(msg.question))
                yield response(msg, code=dns.rcode.NOTIMP)
            elif msg.question[0].rdtype != dns.rdatatype.SOA:
                logging.info("Only supports SOA query, got %d" % dns.rdatatype.to_text(msg.qestion[0].rdtype))
                yield response(msg, code=dns.rcode.NOTIMP)
            else:
                # This happens with nsupdate, if people do not specify a zone.
                # Without the zone, nsupdate sends SOA queries to guess it.
                question = msg.question[0]
                for _, zone in (await backend.get_all_zones()).items():
                    if zone.get("type") and dns.rdatatype.from_text(zone.get("type")) != question.rdtype:
                        continue
                    if await backend.is_in_zone(zone["name"], question.name.to_text(omit_final_dot=True)):
                        res = dns.message.make_response(msg)
                        res.flags |= dns.flags.AA
                        soa_data = dns.rdtypes.ANY.SOA.SOA(
                            question.rdclass,
                            question.rdtype,
                            mname=dns.name.from_text(zone["hostname"]),
                            rname=dns.name.from_text(""),
                            serial=zone.get("serial", 0),
                            refresh=zone.get("ttl", frontend.default_ttl),
                            retry=0,
                            expire=0,
                            minimum=0,
                        )
                        rrset = dns.rrset.from_rdata(question.name, soa_data.refresh, soa_data)
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
                logging.info("Rejected %s: FIXME: prereqs do not work" % cli)
                yield response(msg, code=dns.rcode.NOTIMP)
            # section 2 (update)
            else:
                try:
                    await records.validate(zone, msg.update, backend, frontend.minimum_ttl)
                except Exception as e:
                    raise UpdateRejected(str(e))
                await backend.update(cli, zone, msg.update)
                yield response(msg, code=dns.rcode.NOERROR)

    except dns.exception.FormError as e:
        logging.info("Rejected %s: %s" % (cli, e))
        yield response(msg, code=dns.rcode.FORMERR)

    except dns.message.UnknownTSIGKey as e:
        logging.info("Rejected %s: %s" % (cli, e))
        yield response(msg, code=dns.rcode.REFUSED)

    except UpdateRejected as e:
        logging.info("Rejected %s: %s" % (cli, e))
        yield response(msg, code=dns.rcode.NOTIMP)

    except:
        logging.exception("Rejected %s: Internal error" % cli)
        yield response(msg, code=dns.rcode.SERVFAIL)


class TCPHandler:
    def __init__(self, frontend):
        self.frontend = frontend

    async def handle_tcp(self, reader, writer):
        addr = writer.transport.get_extra_info("peername")
        while True:
            try:
                (size,) = struct.unpack("!H", await reader.readexactly(2))
            except asyncio.IncompleteReadError:
                break
            data = await reader.readexactly(size)
            async for result in handle_nsupdate(self.frontend, data, addr):
                bsize = struct.pack("!H", len(result))
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
        hostname="0.0.0.0",
        port=8053,
        enable_tcp=True,
        enable_udp=True,
        default_ttl=300,
        minimum_ttl=120,
    ):
        self.hostname = hostname
        self.port = port
        self.enable_tcp = enable_tcp
        self.enable_udp = enable_udp
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
            transport, _protocol = await loop.create_datagram_endpoint(lambda: DatagramProtocol(self), local_addr=(self.hostname, self.port))
            host = transport.get_extra_info("sockname")
            urls.append(f"udp://{host[0]}:{host[1]}")

        logging.info("====================")
        for url in urls:
            logging.info("%s", url)
        logging.info("====================")

        logging.info("Servers started")
        return tasks
