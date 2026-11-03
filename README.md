# Rust audit netlink protocol

The `netlink-packet-audit` crate provides netlink messages parsing for
[audit][audit_man] protocol.

[audit_man]: https://man7.org/linux/man-pages/man3/audit_open.3.html

## Capturing audit netlink packets

`nlmon` cannot capture `NETLINK_AUDIT` packets: the kernel's netlink monitor
tap only allows a fixed whitelist of netlink protocols, and
`NETLINK_AUDIT` is not part of it. Use an `AF_NETLINK` socket with the
`NETLINK_AUDIT` protocol instead.

The following example sends `AUDIT_GET` and prints the raw kernel reply.
Run it as root, since audit control requires `CAP_AUDIT_CONTROL`.

```python
import select
import socket
import struct

NETLINK_AUDIT = 9
AUDIT_GET = 1000
NLM_F_REQUEST = 1

sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
sock.bind((0, 0))

header = struct.pack("=IHHII", 16, AUDIT_GET, NLM_F_REQUEST, 1, 0)
sock.send(header)

ready, _, _ = select.select([sock], [], [], 5)
if not ready:
    raise SystemExit("no reply")
print(sock.recv(65535).hex(" "))
```

To capture kernel audit records (multicast events), subscribe to
`AUDIT_NLGRP_READLOG` (group 1) instead of group 0:

```python
sock.bind((0, 1))  # AUDIT_NLGRP_READLOG
```

Make sure auditing is enabled (`auditctl -e 1`) and run as root with
`CAP_AUDIT_READ`. Captured packets can be used directly in unit tests: strip
the 16-byte netlink header for payload-level parsing, or keep it for a full
`NetlinkMessage` round trip.
