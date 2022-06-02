import asyncio
import logging

from . import backends


class Server:
    """
    This is the main duppy Server class. You are expected to subclass
    this to adapt the server to your local setup.

    The default methods assume an SQL-style backend, and expect a
    subclass to set the sql_* variables to appropriate SQL statements
    matching your local schema. If you aren't using SQL, you may need
    to override the delete_*, add_to_rrset and notify_changed methods
    directly.
    """

    # App settings, defaults
    listen_on    = '0.0.0.0'
    http_port    = 5380
    http_updates = True
    http_simple  = True
    rfc2136_port = 8053
    rfc2136_tcp  = True
    rfc2136_udp  = True
    upstream_dns = None
    log_level    = logging.INFO
    minimum_ttl  = 120
    def_ddns_ttl = 300

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

    BACKENDS = {
        'aiopg': backends.PGBackend,
        'aiomysql': backends.MySQLBackend,
        'sqlite3': backends.SQLiteBackend}

    def __init__(self):
        self.db = None
        if self.sql_db_driver in self.BACKENDS:
            self.db = self.BACKENDS[self.sql_db_driver](self)
        elif self.sql_db_driver is not None:
            raise ValueError('Unknown DB driver: %s' % self.sql_db_driver)

    def is_in_zone(self, zone, dns_name):
        """
        Returns True if the DNS name (hostname) is in the given zone, False
        otherwise.

        Override this if your setup has custom rules for this (e.g. treating
        dashes as a subdomain separator).
        """
        return ((zone == dns_name)
            or  (dns_name.endswith('.' + zone)))

    async def transaction_start(self, zone):
        """
        Starts a transaction and returns a handle representing it. This
        handle will be passed as an argument to subsequent database
        operations.
        """
        if self.db:
            return await self.db.start_transaction()
        return None

    async def transaction_commit(self, transaction, zone):
        """
        Commit a set of changes to the database (end transaction).
        """
        if transaction:
            return await transaction.commit()
        return True

    async def transaction_rollback(self, transaction, zone, silent=False):
        """
        Cancel a set of changes to the database (abort transaction).
        """
        if not (transaction and await transaction.rollback()):
            if not silent:
                logging.error(
                    'Rollback failed: zone %s may be in inconsistent state'
                    % (zone,))
            return False
        return True

    async def get_keys(self, zone):
        """
        Fetch the current valid keys for a given zone, as a list.
        """
        if self.db and self.sql_get_keys:
            return [
                row[0] for row in
                await self.db.select(self.sql_get_keys, zone=zone)]
        return []

    async def delete_all_rrsets(self, transaction, zone, dns_name):
        """
        Delete all records for a given DNS name.
        """
        if transaction and self.sql_delete_all_rrsets:
            await transaction.sql(self.sql_delete_all_rrsets,
                zone=zone,
                dns_name=dns_name)
            return True
        return False

    async def delete_rrset(self, transaction, zone, dns_name, rtype):
        """
        Delete all records of a specific type, for a given DNS name.
        """
        if transaction and self.sql_delete_rrset:
            await transaction.sql(self.sql_delete_rrset,
                zone=zone,
                dns_name=dns_name,
                rtype=rtype)
            return True
        return False

    async def delete_from_rrset(self, transaction, zone, dns_name, rtype, rdata):
        """
        Delete all records of a specific type matching the given data,
        for a given DNS name. Note that for SRV and MX records, the
        priority, port and weight are not included (ignored).
        """
        if transaction and self.sql_delete_from_rrset:
            await transaction.sql(self.sql_delete_from_rrset,
                zone=zone,
                dns_name=dns_name,
                rtype=rtype,
                rdata=rdata)
            return True
        return False

    async def add_to_rrset(self,
            transaction, zone, dns_name, rtype, ttl, i1, i2, i3, rdata):
        """
        Add records of a specific type, to a given DNS name.
        """
        if transaction and self.sql_add_to_rrset:
            await transaction.sql(self.sql_add_to_rrset,
                zone=zone,
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
        """
        This is called at the end of an update, if changes have been made.
        Subclasses may want to override this, to invoke custom logic to
        notify secondary DNS servers they need to check for updates.
        """
        if transaction and self.sql_notify_changed:
            await transaction.sql(self.sql_notify_changed, zone=zone)
        return True

    async def startup_tasks(self):
        """
        Subclasses can override this to perform tasks after the event loop
        has started (so async works), but before the DNS and HTTP servers
        have started running.
        """
        pass

    async def get_dns_server_tasks(self):
        """
        Subclasses can override this to return their own DNS server task.
        """
        from . import dns_updates
        return await dns_updates.AsyncDnsUpdateServer(self)

    async def get_http_server_tasks(self):
        """
        Subclasses can override this to return their own HTTP server task.
        """
        from . import http_updates
        return [await http_updates.AsyncHttpApiServer(self).run()]

    async def main(self):
        await self.startup_tasks()

        tasks = []
        if self.rfc2136_port:
            tasks.extend(await self.get_dns_server_tasks())
        if self.http_port:
            tasks.extend(await self.get_http_server_tasks())

        logging.debug('%s' % tasks)
        await asyncio.wait(tasks)

    def run(self):
        """
        Starts the asyncio loop, running the duppy.Server.main() task.
        """
        logging.basicConfig(level=self.log_level)
        loop = asyncio.get_event_loop()
        loop.create_task(self.main())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
