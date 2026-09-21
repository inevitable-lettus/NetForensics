import type { Seal } from "../types";

export function SealPanel({ seal }: { seal: Seal }) {
  const pending = seal.timestamp_status === "pending";
  return (
    <section>
      <h2>Evidence seal</h2>
      <dl>
        <dt>File</dt>
        <dd>{seal.pcap_filename} ({seal.pcap_size_bytes.toLocaleString()} bytes)</dd>
        <dt>BLAKE3</dt>
        <dd className="mono">{seal.pcap_hash}</dd>
        <dt>SHA-256</dt>
        <dd className="mono">{seal.sha256_hash}</dd>
        <dt>Received (UTC)</dt>
        <dd>{seal.received_at}</dd>
        <dt>Trusted timestamp</dt>
        <dd className={pending ? "pending" : "granted"}>
          {pending ? "PENDING — not yet timestamped by a TSA" : `Granted by ${seal.tsa_url}`}
        </dd>
      </dl>
    </section>
  );
}
