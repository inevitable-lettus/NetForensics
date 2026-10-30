# Sample PCAPs

Curated captures for exercising each detector (open risk #2 in
[`../docs/handoff.md`](../docs/handoff.md)). **No capture is committed**: `*.pcap` is
git-ignored. Synthetic ones are generated; real ones are downloaded and verified.

```
python scripts/make_synthetic_pcaps.py   # 4 tiny deterministic files, no network
python scripts/fetch_sample_pcaps.py     # 9 real captures, SHA-256 verified (~25 MB)
```

Expected findings below were measured with `backend.pipeline.analyze_pcap` on
2026-10-20 (main `63ac526` plus this branch), default `CONFIG` thresholds.

## Synthetic (we author them: no licence issue)

Seeded and built from a fixed epoch, so bytes and seal hash are stable.
`tests/test_synthetic_sample_pcaps.py` asserts each fires only its own detector.

| File | Size | Expected findings |
|---|---|---|
| `synthetic-benign.pcap` | 4.5 KB | none (short lookups, human-irregular gaps) |
| `synthetic-dns-exfil.pcap` | 15.6 KB | `dns_exfil` HIGH (120 queries/60s, 40-char random labels) |
| `synthetic-c2-beacon.pcap` | 1.4 KB | `c2_beacon` MEDIUM (20 connections, 60s +/-1s) |
| `synthetic-port-scan.pcap` | 14.0 KB | `port_scan` MEDIUM (200 ports in ~5s). Probe gaps are jittered on purpose: an evenly paced scan also trips `c2_beacon` (risk #8) |

## Real captures (downloaded, never committed)

| File | Size | Expected findings | Source and licence |
|---|---|---|---|
| `ctu-130-1-beacon.pcap` | 8.1 MB | `c2_beacon` MEDIUM: 10.0.2.104 to 54.245.114.184 every ~9s over 6,949 connections, CV 0.020 | CTU-Malware-Capture-Botnet-130-1 (MSIL/Spy.Agent on Windows 7), Stratosphere Laboratory, CTU Prague. CC BY: cite Garcia et al. 2014 and the dataset |
| `ctu-120-1-hostscan.pcap` | 9.8 MB | `port_scan` MEDIUM: 10.0.2.104 reached 10 hosts (4 ports) in 10s. Fires on the host threshold, not the port one | CTU-Malware-Capture-Botnet-120-1, same terms |
| `ctu-185-1-ssdp-falsepositive.pcap` | 6.0 MB | Benign SSDP multicast (192.168.1.2 to 239.255.255.250 every 120s, CV 0.000) used to fire `c2_beacon` MEDIUM. Fixed by the multicast CIDR allowlist (issue #17): expected **no findings** now; kept as the regression target | CTU-Malware-Capture-Botnet-185-1, same terms |
| `ctu-103-nofindings.pcap` | 0.6 MB | none (10 flows, too few for any rule). Infected host but nothing detectable | CTU-Malware-Capture-Botnet-103, same terms |
| `dns-dns2tcp.pcap` | 4.5 KB | `dns_exfil` HIGH (subdomains of hsc.fr) | dmachard/datasets-malicious-dns, pinned commit `b8f90de`. **No licence file in the repo** |
| `dns-dnsextrator.pcap` | 8.8 KB | `dns_exfil` HIGH | same |
| `dns-sods.pcap` | 191 KB | `dns_exfil` HIGH (487 flows) | same |
| `dns-dnscat2.pcap` | 3.6 KB | `c2_beacon` MEDIUM only (12 queries at ~1s). Too short for `dns_exfil`: a real gap | same |
| `dns-iodine.pcap` | 3.5 KB | **crashes the parser**, see below | same |

CTU data: <https://www.stratosphereips.org/datasets-overview>, mirror
<https://mcfp.felk.cvut.cz/publicDatasets/> (index says CC BY; the dataset FAQ says
use needs citation, not permission). The Stratosphere captures are real malware
traffic with some Windows lab-VM noise; read the per-capture README before quoting.

## Why nothing third-party is committed

- All real files are over, or close to, the 5 MB line, and the CTU terms require
  attribution that a bare file in `git` does not carry.
- The DNS-tunnel captures have **no licence** (GitHub reports none), so they are
  URL + pinned hash only. If the owner adds a licence they can be committed.
- `mcfp.felk.cvut.cz` serves an incomplete TLS chain, so the fetch script skips
  certificate verification **for that host only** and relies on the pinned SHA-256
  to authenticate the bytes. GitHub downloads are verified normally.

## Known issues these files expose

1. **`dns-iodine.pcap` raises `UnicodeDecodeError`** inside the DNS parse
   (a label with a non-UTF-8 byte, from `dpkt`'s name decoding). `analyze_pcap`
   dies, so an upload of such a capture would fail. Same for elastic/examples
   `dns-tunnel-iodine.pcap` (Apache-2.0, 77 KB, not included for that reason).
2. ~~SSDP multicast triggers a C2 false positive~~ (`ctu-185-1`): fixed, issue #17.
3. **DNS exfil needs volume**: `dns-dnscat2.pcap` has tunnel traffic
   but only 12 queries, below the rate/length corroboration needed.
4. **JA3: no sample yet.** No licence-clear small capture with a known abuse.ch
   SSLBL match was found. Note the SSLBL JA3 CSV header reads "Last updated:
   2021-08-03", so the feed may be stale. Check before building the JA3 detector.
   Plan: generate a ClientHello pcap ourselves, same way as the synthetic ones.

`sslbl_ja3.cache` (the locally cached abuse.ch JA3 blocklist) also lives here and
is git-ignored.
