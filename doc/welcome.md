# Dynamic DNS update service

This is a [duppy](https://github.com/pagekite/duppy/) server, for
[dynamically updating DNS records](https://en.wikipedia.org/wiki/Dynamic_DNS).

| [Simple HTTP updates](#simple)                                   | **enabled** | HTTP GET [/dnsup/v1/simple](/dnsup/v1/simple) |
| ---------------------------------------------------------------- | -- | -- |
| [HTTP API updates](#update)                                      | **enabled** | HTTP POST [/dnsup/v1/update](/dnsup/v1/update) |
| ---------------------------------------------------------------- | -- | -- |
| [RFC2136 updates](https://datatracker.ietf.org/doc/html/rfc2136) | **enabled** | DNS on port 8053 |

Check your provider's documentation, or the
[duppy Wiki](https://github.com/pagekite/duppy/wiki) for more information.

You will need to obtain an access token / secret key from your provider
before you can make use of this service.</a>.

------------------------------------------------------------------------------

<a name="simple"></a>

## Simple updates:


    GET https://u:p@127.0.0.2:5380/dnsup/v1/simple?hostname=...&myip=...

The username should be the zone, and the password is the
secret key (auth token). These should be sent using HTTP Basic
authentication.

Both hostname and myip can have multiple (comma separated)
values. IPv4 and IPv6 addresses are both supported.

FIXME: Discuss returned values

Responses are appropriate HTTP status codes and a plain/text
summary.

Set `duppy.Server.http_simple = False` to disable.


---------


<a name="update"></a>

## HTTP API updates:


    POST https://127.0.0.2:5380/dnsup/v1/update

The posted data must be JSON, looking something like this:

    {
        "zone": "example.org",
        "key": "+fnQhoAij/FNM0yCANXkKnxZCNIL7XI2yYRJokvTn+U=",
        "updates": [
            {
                "dns_name": "example.org",
                "op": "delete",
                "type": "MX"
            },
            {
                "dns_name": "example.org",
                "op": "add",
                "type": "MX",
                "priority": 10,
                "data": "mail.example.org"
            },
                ...
        ]
    }


Supported ops are `delete` and `add`. The most common record
types (A, AAAA, CNAME, MX, SRV, TXT) are supported. There can be
as many update operations as you need, but all must apply to DNS
names within the same zone.

MX additions require the extra paramter `priority`, SRV requires
`priority`, `weight` and `port`, in addition to the common `data`.

When deleting, adding `type` and `data` can be used to narrow
the scope of the deletion.

The secret key (auth token) can alternately be provided as a
Bearer token in the HTTP Authorization header, or as a
query-string argument named `key`.

FIXME: Discuss returned values

Set `duppy.Server.http_updates = False` to disable.
