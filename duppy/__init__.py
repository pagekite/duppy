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


class FakeSQLBackend:
    def __init__(self, duppy):
        self.duppy = duppy

    def sql(self, what, **kwargs):
        print(what % kwargs)


class Server:
    # App settings, defaults
    listen_on    = '0.0.0.0'
    http_port    = 8053
    rfc2136_port = 5353
    upstream_dns = None
    log_level    = logging.DEBUG

    # Database settings
    sql_db_driver   = None
    sql_db_host     = None
    sql_db_database = None
    sql_db_username = None
    sql_db_password = None

    # Database operations
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

    async def delete_all_rrsets(self, dns_name):
        if self.db and self.sql_delete_all_rrsets:
            await self.db.sql(self.sql_delete_all_rrsets,
                dns_name=dns_name)

    async def delete_rrset(self, dns_name, rtype):
        if self.db and self.sql_delete_rrset:
            await self.db.sql(self.sql_delete_rrset,
                dns_name=dns_name,
                rtype=rtype)

    async def delete_from_rrset(self, dns_name, rtype, rdata):
        if self.db and self.sql_delete_from_rrset:
            await self.db.sql(self.sql_delete_from_rrset,
                dns_name=dns_name,
                rtype=rtype,
                rdata=rdata)

    async def add_to_rrset(self, dns_name, rtype, ttl, prio, rdata):
        if self.db and self.sql_add_to_rrset:
            await self.db.sql(self.sql_add_to_rrset,
                dns_name=dns_name,
                rtype=rtype,
                ttl=ttl,
                prio=prio,
                rdata=rdata)

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
        loop = asyncio.get_event_loop()
        logging.basicConfig(level=self.log_level)
        loop.create_task(self.main())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        loop.close()
