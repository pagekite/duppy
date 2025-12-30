import typing

import dns.immutable
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.MX
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.IN.SRV
import dns.rrset
import dns.ttl


@dns.immutable.immutable
class SOA(dns.rdtypes.ANY.SOA.SOA):
    @classmethod
    def from_json(cls, rdclass, rdtype, obj):
        return cls(
            rdclass,
            rdtype,
            mname=obj["mname"],
            rname=obj["rname"],
            serial=obj["serial"],
            refresh=obj["refresh"],
            retry=obj["retry"],
            expire=obj["expire"],
            minimum=obj["minimum"],
        )


@dns.immutable.immutable
class A(dns.rdtypes.IN.A.A):
    @classmethod
    def from_json(cls, rdclass, rdtype, obj):
        return cls(
            rdclass,
            rdtype,
            address=obj["data"],
        )

    def get_data(self):
        return self.address


@dns.immutable.immutable
class AAAA(dns.rdtypes.IN.AAAA.AAAA):
    @classmethod
    def from_json(cls, rdclass, rdtype, obj):
        return cls(
            rdclass,
            rdtype,
            address=obj["data"],
        )

    def get_data(self):
        return self.address


@dns.immutable.immutable
class CNAME(dns.rdtypes.ANY.CNAME.CNAME):
    @classmethod
    def from_json(cls, rdclass, rdtype, obj):
        return cls(
            rdclass,
            rdtype,
            target=obj["data"],
        )

    def get_data(self):
        return self.target.to_text()


@dns.immutable.immutable
class MX(dns.rdtypes.ANY.MX.MX):
    @classmethod
    def from_json(cls, rdclass, rdtype, obj):
        return cls(
            rdclass,
            rdtype,
            preference=obj["priority"],
            exchange=obj["data"],
        )

    def get_data(self):
        return self.exchange.to_text()


@dns.immutable.immutable
class SRV(dns.rdtypes.IN.SRV.SRV):
    @classmethod
    def from_json(cls, rdclass, rdtype, obj):
        return cls(
            rdclass,
            rdtype,
            priority=obj["priority"],
            weight=obj["weight"],
            port=obj["port"],
            target=obj["data"],
        )

    def get_data(self):
        return self.target.to_text()


@dns.immutable.immutable
class TXT(dns.rdtypes.ANY.TXT.TXT):
    @classmethod
    def from_json(cls, rdclass, rdtype, obj):
        return cls(
            rdclass,
            rdtype,
            strings=obj["data"],
        )

    def get_data(self):
        return self.strings


# Register our extended classes to be found by dns.rdata.get_rdata_class()
dns.rdata._rdata_classes = {
    (dns.rdataclass.IN, dns.rdatatype.SOA): SOA,
    (dns.rdataclass.IN, dns.rdatatype.A): A,
    (dns.rdataclass.IN, dns.rdatatype.AAAA): AAAA,
    (dns.rdataclass.IN, dns.rdatatype.CNAME): CNAME,
    (dns.rdataclass.IN, dns.rdatatype.MX): MX,
    (dns.rdataclass.IN, dns.rdatatype.SRV): SOA,
}


def rdata_from_json(
    rdclass: dns.rdataclass.RdataClass | str,
    rdtype: dns.rdatatype.RdataType | str,
    obj: dict,
) -> dns.rdata.Rdata:
    rdclass = dns.rdataclass.RdataClass.make(rdclass)
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    cls = dns.rdata.get_rdata_class(rdclass, rdtype)
    assert cls is not None  # for type checkers
    return cls.from_json(rdclass, rdtype, obj)


def rrset_from_json(
    obj: dict,
) -> dns.rrset.RRset:
    name = dns.name.from_text(obj["dns_name"])
    ttl = dns.ttl.make(obj.get("ttl", 0))
    rdclass = dns.rdataclass.IN
    rdtype = dns.rdatatype.RdataType.make(obj.get("type", "ANY"))
    deleting = None
    empty = None
    if obj["op"] == "delete":
        # See RFC2136 Section 2.5 and dns.update.UpdateMessage._parse_rr_header()
        if rdtype == dns.rdatatype.ANY or not obj.get("data"):
            deleting = dns.rdataclass.ANY
        else:
            deleting = dns.rdataclass.NONE
        # See dns.message._WireReader._get_section()
        empty = deleting == dns.rdataclass.ANY
    if empty:
        rd = None
    else:
        rd: dns.rdata.Rdata = rdata_from_json(rdclass, rdtype, obj)
    r = dns.rrset.RRset(name, rdclass, rdtype, deleting=deleting)
    if rd is not None:
        r.add(rd, ttl)
    return r


async def validate(zone: dns.name.Name, records: typing.Iterable[dns.rrset.RRset], backend: typing.Any, minimum_ttl: int):
    for r in records:
        if not await backend.is_in_zone(zone.to_text(), r.name.to_text()):
            raise Exception("Not in zone %s: %s" % (zone.to_text(), r.name.to_text()))

        if r.deleting is None:
            if r.ttl < minimum_ttl:
                raise Exception("TTL too low: %d < %d" % (r.ttl, minimum_ttl))
        else:
            if r.ttl != 0:
                raise dns.exception.FormError(f"Invalid TTL {r.ttl} for deletion rate")

        if r.name == zone and r.rdtype == dns.rdatatype.ANY:
            raise Exception("Refused to delete entire zone: %s" % zone)
