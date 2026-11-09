import { utc, bytes } from "../format";
import type { Seal } from "../types";
import { StatusMark } from "./StatusMark";

export function SealPanel({ seal }: { seal: Seal }) {
  const pending = seal.timestamp_status === "pending";
  return (
    <section className="panel" aria-labelledby="seal-title">
      <h2 id="seal-title" className="panel-title">Evidence seal</h2>
      <dl className="facts">
        <dt>File</dt>
        <dd>{seal.pcap_filename} <span className="muted">· {bytes(seal.pcap_size_bytes)}</span></dd>
        <dt>BLAKE3</dt>
        <dd className="mono hash">{seal.pcap_hash}</dd>
        <dt>SHA-256</dt>
        <dd className="mono hash">{seal.sha256_hash}</dd>
        <dt>Received</dt>
        <dd className="mono">{utc(seal.received_at)}</dd>
        <dt>Timestamp</dt>
        <dd className="stamp">
          <StatusMark state={pending ? "pending" : "pass"} />
          {pending ? (
            <span><strong>Pending.</strong> No timestamp authority has signed this seal yet; it is retried later.</span>
          ) : (
            <span>Signed by {seal.tsa_url} at <span className="mono">{utc(seal.timestamp_gen_time)}</span></span>
          )}
        </dd>
      </dl>
    </section>
  );
}
