# This is a sample Duppy server.
#
# Since every backend is a special snowflake, you will need to
# customize this file and write some SQL.
#
# See the examples/ folder for more detailed examples.
#
import duppy


TEST_KEYS = {
    'example.com' : ['+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U='],
    'example.org' : ['+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U=']
}

MOCK_ZONE = []


class MockServer(duppy.Server):

    # App settings
    listen_on    = '127.0.0.2'
    http_port    = 53080      # Set to None to disable the HTTP server
    rfc2136_port = 53053      # Set to None to disable the RFC2136 server
    upstream_dns = None

    # No database, we're writing our own Python code!
    sql_db_driver = None

    async def get_keys(self, zone):
        while zone[-1:] == '.':
            zone = zone[:-1]
        if zone in TEST_KEYS:
            return TEST_KEYS[zone]
        else:
            logging.debug('Zone %s unavailable for updates' % zone)
            return []

    async def delete_all_rrsets(self, dns_name):
        global MOCK_ZONE
        MOCK_ZONE = [rr for rr in MOCK_ZONE if rr[0] == dns_name]
        return True

    async def delete_rrset(self, dns_name, rtype):
        global MOCK_ZONE
        MOCK_ZONE = [rr for rr in MOCK_ZONE
            if rr[0] == dns_name
            and rr[1] == rtype]
        return True

    async def delete_from_rrset(self, dns_name, rtype, rdata):
        global MOCK_ZONE
        MOCK_ZONE = [rr for rr in MOCK_ZONE
            if rr[0] == dns_name
            and rr[1] == rtype
            and rr[-1] == rdata]
        return True

    async def add_to_rrset(self, dns_name, rtype, ttl, i1, i2, i3, rdata):
        global MOCK_ZONE
        rr = [dns_name, rtype, ttl, i1, i2, i3, rdata]
        if rr not in MOCK_ZONE:
            MOCK_ZONE.append(rr)
        return True


try:
    MockServer().run()
finally:
    print('\nMock zone:\n%s' % '\n'.join('%s' % rr for rr in MOCK_ZONE))
