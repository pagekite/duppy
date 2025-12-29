# This is a sample Duppy server, using custom logic and an in-memory
# database of records.
#
# This is mostly useful for testing Duppy itself, but it nicely
# demonstrates how you would implement support for backends that don't
# fit our simplistic SQL defaults.
#
# See the examples/ folder for more examples.
#
import duppy
import logging


TEST_KEYS = {
    "foo": "FM4d4LDAs9jP/N8EkvhhayqtqcO4tUJzvxsPyG20fkCE7g2IizVaTdeAwudLkwvhVECo50te6gJKhoxJkqUMOA==",
    "bar": "QlRlQTl4OA46nPX0/QEk65AECEbreeF8K7guyr5bAsk=",
    "other": "+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U=",
}

TEST_ZONES = {
    "example.com": [
        "foo",
        "bar",
        "other",
    ],
    "example.org": [
        "other",
    ],
}

MOCK_ZONE = []


class MockServer(duppy.Server):

    # App settings
    listen_on = '127.0.0.2'

    # No database, we're writing our own Python code!
    sql_db_driver = None

    # We don't support transactions, so we don't implement these
    #   - transaction_start
    #   - transaction_commit
    #   - transaction_rollback

    async def get_all_zones(self):
        return {zone: {"name": zone, "hostname": zone} for zone in TEST_ZONES.keys()}

    async def get_all_keys(self):
        return TEST_KEYS

    async def get_keys(self, zone):
        if zone in TEST_ZONES:
            return {key: TEST_KEYS[key] for key in TEST_ZONES[zone]}
        else:
            logging.debug("Zone %s unavailable for updates" % zone)
            return []

    async def delete_all_rrsets(self, dbT, zone, dns_name):
        global MOCK_ZONE
        MOCK_ZONE = [rr for rr in MOCK_ZONE if rr[0] == dns_name]
        return True

    async def delete_rrset(self, dbT, zone, dns_name, rtype):
        global MOCK_ZONE
        MOCK_ZONE = [rr for rr in MOCK_ZONE
            if rr[0] != dns_name
            or rr[1] != rtype]
        return True

    async def delete_from_rrset(self, dbT, zone, dns_name, rtype, rdata):
        global MOCK_ZONE
        MOCK_ZONE = [rr for rr in MOCK_ZONE
            if rr[0] != dns_name
            or rr[1] != rtype
            or rr[-1] != rdata]
        return True

    async def add_to_rrset(self, dbT, zone, dns_name, rtype, ttl, i1, i2, i3, rdata):
        global MOCK_ZONE
        rr = [dns_name, rtype, ttl, i1, i2, i3, rdata]
        if rr not in MOCK_ZONE:
            MOCK_ZONE.append(rr)
        return True

    async def notify_changed(self, dbT, zone):
        print('*** Zone changed %s ***' % zone)
        print('%s' % '\n'.join('%s' % rr for rr in MOCK_ZONE))
        print('***')
        return True


try:
    MockServer().run()
finally:
    print('\nMock zone:\n%s' % '\n'.join('%s' % rr for rr in MOCK_ZONE))
