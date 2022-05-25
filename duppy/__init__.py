import asyncio
import logging

from . import backends


class Server:
    # App settings, defaults
    listen_on    = '0.0.0.0'
    http_port    = 5380
    rfc2136_port = 8053
    rfc2136_tcp  = True
    rfc2136_udp  = True
    upstream_dns = None
    log_level    = logging.INFO
    minimum_ttl  = 120

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
    sql_notify_changed = None

    def __init__(self):
        self.db = None
        if self.sql_db_driver == 'aiopg':
            self.db = backends.PGBackend(self)
        elif self.sql_db_driver == 'aiomysql':
            self.db = backends.MySQLBackend(self)
        elif self.sql_db_driver is not None:
            raise ValueError('Unknown DB driver: %s' % self.sql_db_driver)

    async def transaction_start(self, zone):
        if self.db:
            return await self.db.start_transaction()
        return None

    async def transaction_commit(self, transaction, zone):
        if transaction:
            await transaction.commit()

    async def transaction_rollback(self, transaction, zone, silent=False):
        if not (transaction and await transaction.rollback()):
            if not silent:
                logging.error(
                    'Rollback failed: zone %s may be in inconsistent state'
                    % (zone,))

    async def get_keys(self, zone):
        if self.db and self.sql_get_keys:
            return await self.db.select(self.sql_get_keys, zone=zone)
        return []

    async def delete_all_rrsets(self, transaction, dns_name):
        if transaction and self.sql_delete_all_rrsets:
            await transaction.sql(self.sql_delete_all_rrsets,
                dns_name=dns_name)
            return True
        return False

    async def delete_rrset(self, transaction, dns_name, rtype):
        if transaction and self.sql_delete_rrset:
            await transaction.sql(self.sql_delete_rrset,
                dns_name=dns_name,
                rtype=rtype)
            return True
        return False

    async def delete_from_rrset(self, transaction, dns_name, rtype, rdata):
        if transaction and self.sql_delete_from_rrset:
            await transaction.sql(self.sql_delete_from_rrset,
                dns_name=dns_name,
                rtype=rtype,
                rdata=rdata)
            return True
        return False

    async def add_to_rrset(self,
            transaction, dns_name, rtype, ttl, i1, i2, i3, rdata):
        if transaction and self.sql_add_to_rrset:
            await transaction.sql(self.sql_add_to_rrset,
                dns_name=dns_name,
                rtype=rtype,
                ttl=ttl,
                i1=i1,
                i2=i2,
                i3=i3,
                rdata=rdata)
            return True
        return False

    async def notify_changed(self, transaction, zone):
        if transaction and self.sql_notify_changed:
            await transaction.sql(self.sql_notify_changed, zone=zone)
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
