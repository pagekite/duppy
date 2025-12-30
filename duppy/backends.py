import abc
import logging
import re
import typing

import dns.name
import dns.rdatatype
import dns.rrset


PYTHON_PLACEHOLDER = re.compile(r'%\(([a-z0-9_]+)\)s')


class Backend(abc.ABC):
    @abc.abstractmethod
    async def get_all_zones(self):
        """
        Fetch all zones, as dict zone name, zone info.
        """
        ...

    async def is_in_zone(self, zone, dns_name):
        """
        Returns True if the DNS name (hostname) is in the given zone, False
        otherwise.
        """
        return ((zone == dns_name)
            or  (dns_name.endswith('.' + zone)))

    @abc.abstractmethod
    async def get_all_keys(self) -> dict:
        """
        Fetch the current valid keys, as a dict key_name, key.
        """
        ...

    @abc.abstractmethod
    async def get_keys(self, zone) -> dict:
        """
        Fetch the current valid keys for a given zone, as a dict key_name, key.
        """
        ...

    async def check_key_in_zone(self, key, zone):
        """
        Check if a key is present in a zone.
        """
        keys = await self.get_keys(zone)
        return key in keys

    async def delete_all_rrsets(self, transaction, zone, r: dns.rrset.RRset) -> bool:
        """
        Delete all records for a given DNS name.
        """
        raise NotImplementedError()

    async def delete_rrset(self, transaction, zone, r: dns.rrset.RRset) -> bool:
        """
        Delete all records of a specific type, for a given DNS name.
        """
        raise NotImplementedError()

    async def delete_from_rrset(self, transaction, zone, r: dns.rrset.RRset) -> bool:
        """
        Delete all records of a specific type matching the given data,
        for a given DNS name. Note that for SRV and MX records, the
        priority, port and weight are not included (ignored).
        """
        raise NotImplementedError()

    async def add_to_rrset(self, transaction, zone, r: dns.rrset.RRset) -> bool:
        """
        Add records of a specific type, to a given DNS name.
        """
        raise NotImplementedError()

    async def update(self, cli: str, zone: dns.name.Name, updates: typing.Iterable[dns.rrset.RRset]):
        zone_str = zone.to_text(omit_final_dot=True).lower()
        error = None
        try:
            dbT = await self.transaction_start(zone_str)
            changes = 0
            ok = True
            for r in updates:
                if r.deleting:
                    # RFC2136 Section 2.5
                    if r.deleting == dns.rdataclass.ANY and r.rdtype == dns.rdatatype.ANY:
                        logging.info('%s: delete_all_rrsets %s' % (cli, r))
                        ok = await self.delete_all_rrsets(dbT, zone_str, r)
                    elif r.deleting == dns.rdataclass.ANY:
                        logging.info('%s: delete_rrset %s' % (cli, r))
                        ok = await self.delete_rrset(dbT, zone_str, r)
                    elif r.deleting == dns.rdataclass.NONE:
                        logging.info('%s: delete_from_rrset %s' % (cli, r))
                        ok = await self.delete_from_rrset(dbT, zone_str, r)
                else:
                    logging.info('%s: add_to_rrset %s' % (cli, r))
                    ok = await self.add_to_rrset(dbT, zone_str, r)

                if ok:
                    changes += 1
                else:
                    break

            if changes:
                ok = await self.notify_changed(dbT, zone_str) and ok

            if ok and await self.transaction_commit(dbT, zone_str):
                dbT = None
                return
            else:
                raise Exception('Internal Error')
        except Exception as e:
            # Save exception to handle rollback
            error = e
        finally:
            if dbT is not None:
                await self.transaction_rollback(dbT, zone_str, silent=(not changes))
        if error:
            raise error


class TemporaryBackend(Backend):
    async def transaction_start(self, zone) -> typing.Any:
        """
        Starts a transaction and returns a handle representing it. This
        handle will be passed as an argument to subsequent database
        operations.
        """
        return None

    async def transaction_commit(self, transaction, zone) -> bool:
        """
        Commit a set of changes to the database (end transaction).
        """
        return True

    async def transaction_rollback(self, transaction, zone, silent=False) -> bool:
        """
        Cancel a set of changes to the database (abort transaction).
        """
        return True

    async def notify_changed(self, transaction, zone) -> bool:
        """
        This is called at the end of an update, if changes have been made.
        Subclasses may want to override this, to invoke custom logic to
        notify secondary DNS servers they need to check for updates.
        """
        return True


class SQLBackend(TemporaryBackend):
    """
    This is an SQL database back-end.

    It supports %(foo)s style placeholders in SQL queries.
    """
    db: typing.Any = None

    # Database operations
    sql_get_all_keys: str | None = None
    sql_get_all_zones: str | None = None
    sql_get_keys: str | None = None
    sql_delete_all_rrsets: str | None = None
    sql_delete_rrset: str | None = None
    sql_delete_from_rrset: str | None = None
    sql_add_to_rrset: str | None = None
    sql_notify_changed: str | None = None

    def __init__(self, db, queries):
        self.db = db
        for name, query in queries.items():
            setattr(self, name, query)

    async def transaction_start(self, zone) -> typing.Any:
        """
        Starts a transaction and returns a transaction handle.

        The transaction handle must implement the following methods:
        - async def sql(self, query, **kwargs) -> typing.Any
        - async def commit(self) -> bool
        - async def rollback(self) -> bool
        """
        if self.db:
            return await self.db.start_transaction()
        return None

    async def transaction_commit(self, transaction, zone):
        if transaction:
            return await transaction.commit()
        return True

    async def transaction_rollback(self, transaction, zone, silent=False):
        if not (transaction and await transaction.rollback()):
            if not silent:
                logging.error(
                    'Rollback failed: zone %s may be in inconsistent state'
                    % (zone,))
            return False
        return True

    async def get_all_zones(self):
        if self.db and self.sql_get_all_zones:
            return {
                row[0]: {
                    "zone": row[0],
                    "hostname": row[1],
                    "type": row[2],
                    "ttl": row[3],
                    "serial": row[4],
                }
                for row in await self.db.sql(self.sql_get_all_zones)
            }
        return []

    async def get_all_keys(self):
        if self.db and self.sql_get_all_keys:
            return {
                row[0]: row[1]
                for row in await self.db.sql(self.sql_get_all_keys)
            }
        return []

    async def get_keys(self, zone):
        if self.db and self.sql_get_keys:
            return {
                row[0]: row[1]
                for row in await self.db.sql(self.sql_get_keys, zone=zone)
            }
        return []

    async def delete_all_rrsets(self, transaction, zone, r) -> bool:
        dns_name = r.name.to_text(omit_final_dot=True)
        if transaction and self.sql_delete_all_rrsets:
            await transaction.sql(self.sql_delete_all_rrsets,
                zone=zone,
                dns_name=dns_name)
            return True
        return False

    async def delete_rrset(self, transaction, zone, r) -> bool:
        dns_name = r.name.to_text(omit_final_dot=True)
        rtype = dns.rdatatype.to_text(r.rdtype)
        if transaction and self.sql_delete_rrset:
            await transaction.sql(self.sql_delete_rrset,
                zone=zone,
                dns_name=dns_name,
                rtype=rtype)
            return True
        return False

    async def delete_from_rrset(self, transaction, zone, r) -> bool:
        dns_name = r.name.to_text(omit_final_dot=True)
        rtype = dns.rdatatype.to_text(r.rdtype)
        rdata = r[0].get_data()
        if transaction and self.sql_delete_from_rrset:
            await transaction.sql(self.sql_delete_from_rrset,
                zone=zone,
                dns_name=dns_name,
                rtype=rtype,
                rdata=rdata)
            return True
        return False

    async def add_to_rrset(self, transaction, zone, r) -> bool:
        dns_name = r.name.to_text(omit_final_dot=True)
        rtype = dns.rdatatype.to_text(r.rdtype)
        ttl = r.ttl
        i1 = None
        i2 = None
        i3 = None
        if r.rdtype == dns.rdatatype.MX:
            i1 = r[0].preference
        elif r.rdtype == dns.rdatatype.SRV:
            i1 = r[0].priority
            i1 = r[0].weight
            i1 = r[0].port
        rdata = r[0].get_data()
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

    async def notify_changed(self, transaction, zone) -> bool:
        if transaction and self.sql_notify_changed:
            await transaction.sql(self.sql_notify_changed, zone=zone)
        return True


class SQLiteTransaction:
    def __init__(self, backend):
        self.backend = backend

    async def sql(self, query, **kwargs):
        return self.backend.sql(query, **kwargs)

    async def commit(self):
        self.backend._db.commit()
        self.backend = None  # Explode if people keep using us after this
        return True

    async def rollback(self):
        self.backend = None  # Explode if people keep using us after this
        return True


class SQLiteBackend(SQLBackend):
    """
    This is a database back-end, implemented on top of sqlite3.
    """
    def __init__(self, database):
        import sqlite3
        self._db = sqlite3.connect(database)

    def _py_to_sq3_placeholders(self, query):
        return PYTHON_PLACEHOLDER.sub(lambda m: ':'+m.group(1), query)

    async def start_transaction(self):
        if self.nested:
            raise Exception('Started a transaction within a transaction')
        return SQLiteTransaction(self)

    async def sql(self, query, **kwargs):
        query = self._py_to_sq3_placeholders(query)
        return self._db.execute(query, kwargs).fetchall()
