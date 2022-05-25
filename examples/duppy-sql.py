# This is a sample Duppy server, using an sqlite3 database.
#
# Since every backend is a special snowflake, you will need to
# customize this file and write some SQL.
#
# See the examples/ folder for more examples.
#
import duppy
import logging


TEST_KEYS = {
    'example.com' : [
        'FM4d4LDAs9jP/N8EkvhhayqtqcO4tUJzvxsPyG20fkCE7g2IizVaTdeAwudLkwvhVECo50te6gJKhoxJkqUMOA==',
        'QlRlQTl4OA46nPX0/QEk65AECEbreeF8K7guyr5bAsk=',
        '+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U='],
    'example.org' : ['+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U='],
}


class MyServer(duppy.Server):

    # App settings
    listen_on    = '127.0.0.2'
    http_port    = 5380       # Set to None to disable the HTTP server
    rfc2136_port = 8053       # Set to None to disable the RFC2136 server
    upstream_dns = '8.8.8.8'  # Replace with the IP address of your primary DNS

    # Miscellaneous settings.
    log_level    = logging.INFO
    minimum_ttl  = 120

    # Database settings
    sql_db_driver   = 'sqlite3'      # 'aiopg', 'aiomysql' or None
    sql_db_database = '/tmp/duppy-test.sq3'
    # Unused here, but you might need:
    sql_db_host     = None
    sql_db_username = None
    sql_db_password = None

    # Database operations; set any of these to None to disable the operation.
    sql_get_keys = """
        SELECT key FROM zone_keys WHERE zone = %(zone)s
        """
    sql_delete_all_rrsets = """
        DELETE FROM zone_data
              WHERE hostname = %(dns_name)s
                AND zone = %(zone)s
        """
    sql_delete_rrset = """
        DELETE FROM zone_data
              WHERE hostname = %(dns_name)s
                AND type = %(rtype)s
                AND zone = %(zone)s
        """
    sql_delete_from_rrset = """
        DELETE FROM zone_data
              WHERE hostname = %(dns_name)s
                AND type = %(rtype)s
                AND data = %(rdata)s
                AND zone = %(zone)s
        """
    sql_add_to_rrset = """
        INSERT INTO zone_data (zone, hostname, type, ttl, i1, i2, i3, data)
              VALUES (%(zone)s,
                      %(dns_name)s,
                      %(rtype)s,
                      %(ttl)s,
                      %(i1)s,
                      %(i2)s,
                      %(i3)s,
                      %(rdata)s)
        """
    #
    # The following is how we signal that a zone has changed, so secondary
    # servers know they need to update. Set to None if your database handles
    # this automatically using a trigger function.
    #
    # If a DB update is insufficient, and you need to execute some code
    # for this, then override duppy.Server.notify_changed. There is an
    # example of that in `examples/duppy-mock.py`.
    #
    sql_notify_changed = """
        UPDATE zone_data
           SET i1 = ((i1 + 1) % 4294967295) + 1
         WHERE zone = %(zone)s
           AND type = 'SOA'
        """

    async def startup_tasks(self):
        # This defines some test tables to play with. Delete this!
        import sqlite3
        dbT = await self.db.start_transaction()
        try:
            await dbT.sql("""CREATE TABLE zone_keys (zone, key)""")
            await dbT.sql("""CREATE TABLE zone_data (zone, hostname, type, ttl, i1, i2, i3, data)""")
        except sqlite3.OperationalError:
            pass

        await dbT.sql("""DELETE FROM zone_keys""")
        await dbT.sql("""DELETE FROM zone_data""")
        for zone in TEST_KEYS:
            for key in TEST_KEYS[zone]:
                await dbT.sql("""
                    INSERT INTO zone_keys (zone, key)
                         VALUES (%(zone)s, %(key)s)
                    """, zone=zone, key=key)
            await dbT.sql("""
                INSERT INTO zone_data (zone, hostname, type, ttl, i1)
                     VALUES (%(zone)s, %(zone)s, 'SOA', 3600, 1)
                """, zone=zone)

        await dbT.commit()


MyServer().run()
