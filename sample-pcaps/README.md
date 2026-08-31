# Sample PCAPs

Curated captures for exercising each detector. **Each file here must fire at least
one detector** (open risk #2 in [`../docs/handoff.md`](../docs/handoff.md)).
Hand-pick captures from
[malware-traffic-analysis.net](https://malware-traffic-analysis.net) per detector
so no detector goes untested against a real trace.

| File | Fires detector | Source / notes |
|---|---|---|
| _(tbd)_ | dns_exfil | DNS tunneling sample |
| _(tbd)_ | c2_beacon | regular-interval C2 sample |
| _(tbd)_ | port_scan | nmap / recon sample |
| _(tbd)_ | tls_client | JA3 with a known abuse.ch SSLBL match |

> Captures are git-ignored (`*.pcap`, `*.pcapng`) — never commit large or
> licensing-restricted files. Third-party malware-traffic captures may carry
> distribution restrictions; keep them local, do not push them to the repo.

`sslbl_ja3.cache` (the locally cached abuse.ch JA3 blocklist) also lives here and
is git-ignored.
