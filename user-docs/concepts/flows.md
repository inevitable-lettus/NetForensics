# Flows

Detectors never read packets. They read **flows**, built once, in one pass over the capture.

A flow is one connection, identified by its 5-tuple: source address, destination address,
source port, destination port and protocol. Both directions of a conversation fold into one
flow, oriented so the *source* is whoever spoke first. That matters: if replies from a
scanned server became flows of their own, the victim would look like a scanner.

| Field | Meaning |
|---|---|
| `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` | The 5-tuple (`tcp` or `udp`). |
| `start_time`, `end_time` | First and last packet seen, UTC. |
| features | Per-flow numbers detectors use, such as packet counts. DNS flows also carry their queries. |

## What the parser handles

- Classic `.pcap` files with Ethernet framing, IPv4, TCP and UDP.
- TCP starts a new flow when a fresh SYN reappears on the same 5-tuple.
- DNS queries are parsed separately and grouped by parent domain, so the DNS detector can
  look at subdomains.

## What it ignores

- IPv6, pcapng, and any other link or network protocol.
- TCP reassembly: it never rebuilds a byte stream, so it cannot see inside a split message.
- A UDP conversation that reuses one 5-tuple stays one flow however long it lasts.

These are scope decisions, listed in [Limits](../reference/limits.md).
