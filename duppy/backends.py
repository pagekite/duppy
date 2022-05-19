import asyncio
import logging


class PGBackend:
    def __init__(self, duppy):
        import aiopg
        self.duppy = duppy

    async def sql(self, query, **kwargs):
        pass

    async def select(self, query, **kwargs):
        return []


class MySQLBackend:
    def __init__(self, duppy):
        import aiomysql
        self.duppy = duppy

    async def sql(self, query, **kwargs):
        pass

    async def select(self, query, **kwargs):
        return []
