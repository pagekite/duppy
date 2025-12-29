import asyncio
import logging
import re


PYTHON_PLACEHOLDER = re.compile(r'%\(([a-z0-9_]+)\)s')


class SQLiteBackend:
    """
    This is a duppy database back-end, implemented on top of sqlite3.

    It supports %(foo)s style placeholders in SQL queries (same as the
    PostgreSQL and MySQL backends), so this can be used to test/debug
    the SQL statements written for the other backends.
    """
    def __init__(self, duppy, nested=False):
        import sqlite3
        self.duppy = duppy
        self.nested = nested
        self._db = sqlite3.connect(self.duppy.sql_db_database)

    def _py_to_sq3_placeholders(self, query):
        return PYTHON_PLACEHOLDER.sub(lambda m: ':'+m.group(1), query)

    async def start_transaction(self):
        if self.nested:
            raise Exception('Started a transaction within a transaction')
        return SQLiteBackend(self.duppy, nested=True)

    async def commit(self):
        self._db.commit()
        self._db.close()
        self._db = None  # Explode if people keep using us after this
        return True

    async def rollback(self):
        self._db.close()
        self._db = None  # Explode if people keep using us after this
        return True

    async def sql(self, query, **kwargs):
        query = self._py_to_sq3_placeholders(query)
        return self._db.execute(query, kwargs).fetchall()

    async def select(self, query, **kwargs):
        query = self._py_to_sq3_placeholders(query)
        return self._db.execute(query, kwargs).fetchall()


class PGBackend:
    def __init__(self, duppy):
        import aiopg
        self.duppy = duppy

    async def start_transaction(self):
        logging.debug('FIXME: Start transaction, return handle?')
        return self

    async def commit(self):
        # FIXME: This should be a transaction op
        return True

    async def rollback(self):
        # FIXME: This should be a transaction op
        return False

    async def sql(self, query, **kwargs):
        # FIXME: This should be a transaction op
        pass

    async def select(self, query, **kwargs):
        return []


class MySQLBackend(PGBackend):
    def __init__(self, duppy):
        import aiomysql
        self.duppy = duppy
