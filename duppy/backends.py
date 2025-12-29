import asyncio
import logging
import re


PYTHON_PLACEHOLDER = re.compile(r'%\(([a-z0-9_]+)\)s')


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


class SQLiteBackend:
    """
    This is a database back-end, implemented on top of sqlite3.
    """
    def __init__(self, duppy, nested=False):
        import sqlite3
        self.duppy = duppy
        self._db = sqlite3.connect(self.duppy.sql_db_database)

    def _py_to_sq3_placeholders(self, query):
        return PYTHON_PLACEHOLDER.sub(lambda m: ':'+m.group(1), query)

    async def start_transaction(self):
        if self.nested:
            raise Exception('Started a transaction within a transaction')
        return SQLiteTransaction(self)

    async def sql(self, query, **kwargs):
        query = self._py_to_sq3_placeholders(query)
        return self._db.execute(query, kwargs).fetchall()
