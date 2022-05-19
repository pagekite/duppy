# This is a sample Duppy server.
#
# Since every backend is a special snowflake, you will need to
# customize this file and write some SQL.
#
# See the examples/ folder for more detailed examples.
#
import duppy


class MyServer(duppy.Server):

    # App settings
    listen_on    = '127.0.0.2'
    http_port    = 5380       # Set to None to disable the HTTP server
    rfc2136_port = 8053       # Set to None to disable the RFC2136 server
    upstream_dns = '8.8.8.8'  # Replace with the IP address of your primary DNS

    # Database settings
    sql_db_driver   = 'aiopg'      # 'aiopg', 'aiomysql' or None
    sql_db_host     = '127.0.0.1'
    sql_db_database = 'dns'
    sql_db_username = 'dns_updater'
    sql_db_password = '1234abcdefg'

    # Database operations; set any of these to None to disable the operation.
    sql_get_keys = """
        SELECT key FROM zone_keys WHERE zone = %(zone)s
"""
    sql_delete_all_rrsets = """
        DELETE FROM zone_data
              WHERE hostname = %s
        """
    sql_delete_rrset = """
        DELETE FROM zone_data
              WHERE hostname = %(dns_name)s
                AND type = %(rtype)s'
        """
    sql_delete_from_rrset = """
        DELETE FROM zone_data
              WHERE hostname = %(dns_name)s
                AND type = %(rtype)s'
                AND data = %(rdata)s'
        """
    sql_add_to_rrset = """
        INSERT INTO zone_data (hostname, type, ttl, i1, i2, i3, data)
              VALUES (%(dns_name)s,
                      %(rtype)s,
                      %(ttl)s,
                      %(i1)s,
                      %(i2)s,
                      %(i3)s,
                      %(rdata)s)
    """


MyServer().run()
