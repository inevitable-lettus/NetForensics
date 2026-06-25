# Sample PCAPs

Curated demo captures. **Each file here must fire at least one detector** (open
risk #2 in [`../docs/handoff.md`](../docs/handoff.md)). Hand-pick captures from
[malware-traffic-analysis.net](https://malware-traffic-analysis.net) per detector
so no detector shows zero hits on demo day.

| File | Fires detector | Source / notes |
|---|---|---|
| _(tbd)_ | dns_exfil | DNS tunneling sample |
| _(tbd)_ | c2_beacon | regular-interval C2 sample |
| _(tbd)_ | port_scan | nmap / recon sample |
| _(tbd)_ | tls_client | JA3 with a known abuse.ch SSLBL match |

> Do not commit large or licensing-restricted captures to the public history.
> Keep this repo private until pcaps are cleared (see session note).

`sslbl_ja3.cache` (the locally cached abuse.ch JA3 blocklist) also lives here and
is git-ignored.
