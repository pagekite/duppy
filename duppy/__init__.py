import asyncio
import logging


class PGBackend:
    def __init__(self, duppy):
        import aiopg
        self.duppy = duppy


class MySQLBackend:
    def __init__(self, duppy):
        import aiomysql
        self.duppy = duppy


class Server:
    # App settings, defaults
    listen_on    = '0.0.0.0'
    http_port    = 5380
    rfc2136_port = 53
    rfc2136_tcp  = True
    rfc2136_udp  = True
    upstream_dns = None
    log_level    = logging.INFO

    # Database settings
    sql_db_driver   = None
    sql_db_host     = None
    sql_db_database = None
    sql_db_username = None
    sql_db_password = None

    # Database operations
    sql_get_keys = None
    sql_delete_all_rrsets = None
    sql_delete_rrset = None
    sql_delete_from_rrset = None
    sql_add_to_rrset = None

    def __init__(self):
        self.db = None
        if self.sql_db_driver == 'aiopg':
            self.db = PGBackend(self)
        elif self.sql_db_driver == 'aiomysql':
            self.db = MySQLBackend(self)
        elif self.sql_db_driver == 'fake':
            self.db = FakeSQLBackend(self)
        elif self.sql_db_driver is not None:
            raise ValueError('Unknown DB driver: %s' % self.sql_db_driver)

    async def get_keys(self, zone):
        if self.db and self.sql_get_keys:
            return await self.db.select(self.sql_get_keys,
                zone=zone)
        return []

    async def delete_all_rrsets(self, dns_name):
        if self.db and self.sql_delete_all_rrsets:
            await self.db.sql(self.sql_delete_all_rrsets,
                dns_name=dns_name)
            return True
        return False

    async def delete_rrset(self, dns_name, rtype):
        if self.db and self.sql_delete_rrset:
            await self.db.sql(self.sql_delete_rrset,
                dns_name=dns_name,
                rtype=rtype)
            return True
        return False

    async def delete_from_rrset(self, dns_name, rtype, rdata):
        if self.db and self.sql_delete_from_rrset:
            await self.db.sql(self.sql_delete_from_rrset,
                dns_name=dns_name,
                rtype=rtype,
                rdata=rdata)
            return True
        return False

    async def add_to_rrset(self, dns_name, rtype, ttl, i1, i2, i3, rdata):
        if self.db and self.sql_add_to_rrset:
            await self.db.sql(self.sql_add_to_rrset,
                dns_name=dns_name,
                rtype=rtype,
                ttl=ttl,
                i1=i1,
                i2=i2,
                i3=i3,
                rdata=rdata)
            return True
        return False

    async def main(self):
        tasks = []
        if self.rfc2136_port:
            from . import dns_updates
            tasks.extend(await dns_updates.AsyncDnsUpdateServer(self))

        if self.http_port:
            from . import http_updates
            tasks.append(http_updates.AsyncHttpApiServer(self))

        logging.debug('%s' % tasks)
        await asyncio.wait(tasks)

    def run(self):
        logging.basicConfig(level=self.log_level)
        loop = asyncio.get_event_loop()
        loop.create_task(self.main())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
