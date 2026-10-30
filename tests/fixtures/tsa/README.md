# RFC 3161 test fixtures

All files are DER. They are checked in so the timestamp tests run offline.

| File | What it is |
|---|---|
| `freetsa_vector.tsq` | Request built by `timestamp.build_request` for SHA-256 `3880d492…a3e7` (the SHA-256 of `NetForensics RFC 3161 test vector\n`), nonce `0x5EEDF00DCAFEBEEF`, certReq true. |
| `freetsa_vector.tsr` | FreeTSA's real reply to that request, 2026-10-27 09:29:26 UTC. `openssl ts -verify -in freetsa_vector.tsr -queryfile freetsa_vector.tsq -CAfile backend/evidence/certs/freetsa_cacert.pem -untrusted backend/evidence/certs/freetsa_tsa.crt` says `Verification: OK`. |
| `forged_own_ca.tsr` | Reply to the same request signed with `openssl ts -reply` by a home-made CA ("Evil Root CA") and TSA certificate (critical timeStamping usage), with both certificates embedded. Accepted by rfc3161-client 1.0.8 when only the FreeTSA root is configured; refused once the TSA certificate is pinned. |
| `forged_no_ca.tsr` | The same home-made TSA, embedding only its own certificate. |

The home-made keys were throwaway and are not kept; regenerate forgeries with
`openssl req` / `openssl x509 -req` / `openssl ts -reply` if needed. rfc3161-client
requires the embedded certificates in DER SET order, so the CA certificate must
encode longer than the TSA one (a 4096-bit CA key with a 2048-bit TSA key works).
