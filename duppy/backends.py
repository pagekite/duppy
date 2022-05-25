import asyncio
import logging


class PGBackend:
    def __init__(self, duppy):
        import aiopg
        self.duppy = duppy

    async def start(self):
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
