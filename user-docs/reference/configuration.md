# Configuration

All thresholds and settings live in one place, `backend/config.py`. Detectors import them;
none is hard-coded elsewhere. There are no command-line flags or environment variables to
change them: a finding must be reproducible from the capture and the program alone. To use
different values, edit the file (it is a frozen dataclass) and keep the change with the case
notes.

Values marked *proposed* are starting points that have not been tuned against real traffic.

## DNS exfiltration

| Setting | Default | Meaning |
|---|---|---|
| `benign_entropy_baseline` | 2.5 | Where ordinary subdomains sit; quoted in evidence. |
| `entropy_threshold` | 4.2 | Required. Bits per character. |
| `subdomain_length_threshold` | 30 (*proposed*) | Characters; corroborates entropy. |
| `query_rate_threshold` | 50 (*proposed*) | Queries per window to one parent domain; corroborates entropy. |
| `query_rate_window_secs` | 60 | The window the rate is scaled to. |

## C2 beaconing

| Setting | Default | Meaning |
|---|---|---|
| `min_connections` | 10 (*proposed*) | Fewer connections are too few to judge regularity. |
| `max_coefficient_of_variation` | 0.1 (*proposed*) | At or below this, timing counts as machine-regular. |

## Port scan

| Setting | Default | Meaning |
|---|---|---|
| `distinct_ports_threshold` | 100 (*proposed*) | Distinct destination ports in one window. |
| `distinct_hosts_threshold` | 10 (*proposed*) | Distinct destination hosts in one window. |
| `window_secs` | 10 (*proposed*) | Sliding window length. |

## Allowlists

| Setting | Default | Effect |
|---|---|---|
| `dns_parent_domains` | `cloudfront.net`, `akamaihd.net`, `googleusercontent.com`, `amazonaws.com` | DNS findings for these parents (and their subdomains) are suppressed. |
| `beacon_dst_ips` | none | Beacon findings to these destinations are suppressed. |
| `beacon_dst_cidrs` | `224.0.0.0/4`, `255.255.255.255/32` | Multicast and broadcast destinations are skipped by the beacon detector. |

## Ingest

| Setting | Default | Meaning |
|---|---|---|
| `max_upload_bytes` | 512 MiB (*proposed*) | Larger captures are refused. |
| `upload_chunk_bytes` | 1 MiB | Streaming size; a capture is never buffered whole. |

## Evidence layer

| Setting | Default | Meaning |
|---|---|---|
| `hash_algorithm` | `blake3` | Primary seal hash (SHA-256 is always computed too). |
| `hash_chunk_bytes` | 1 MiB | Streaming read size. |
| `tsa_url` | `https://freetsa.org/tsr` | The timestamp authority. |
| `tsa_timeout_secs` | 5 | One total deadline per attempt. |
| `allow_offline_fallback` | true | An unreachable authority gives `PENDING`, never a failure and never a fake. |
| `tsa_max_reply_bytes` | 64 KiB | Larger replies are refused. |
| `tsa_retry_attempts` | 3 | Attempts per case in `retry-timestamps`. |
| `tsa_retry_backoff_secs` / `_max_secs` | 2.0 / 30.0 | Exponential backoff base and cap. |
| `tsa_batch_stop_after_unavailable` | 3 | Cases in a row that find the authority down before a retry run stops. |
| `tsa_cert_path`, `tsa_ca_path` | `backend/evidence/certs/...` | The pinned authority certificate and its CA. |
| `evidence_store_dir` | `evidence_store` | Default store location (`--store` overrides). |
| `db_path` | `evidence_store/netforensics.sqlite` | The database inside the store. |
