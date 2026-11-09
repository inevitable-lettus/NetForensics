import { useState } from "react";
import { verifyCase } from "../api";
import { utc } from "../format";
import type { VerifyResponse } from "../types";
import { CheckList, CheckListSkeleton } from "./CheckList";
import { ShieldIcon } from "./Icons";
import { VerdictBanner } from "./VerdictBanner";

export function VerifyPanel({ caseId }: { caseId: string }) {
  const [result, setResult] = useState<VerifyResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      setResult(await verifyCase(caseId));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <div className="toolbar">
        <p className="muted toolbar-text">
          Re-hashes the stored capture and re-checks the seal, the custody chain, the timestamp and
          the anchored chain head. Each run is recorded in the custody chain, unless the case is altered.
        </p>
        <button type="button" className="btn btn-primary" onClick={run} disabled={busy}>
          {busy ? "Verifying" : result ? "Verify again" : "Verify now"}
        </button>
      </div>
      {error && <p role="alert" className="inline-error">{error}</p>}
      {busy && <CheckListSkeleton />}
      {!busy && !result && !error && (
        <div className="empty">
          <ShieldIcon className="empty-icon" />
          <p className="empty-title">Not verified in this session</p>
          <p className="muted">Run a verification to see all five checks with the values they compared.</p>
        </div>
      )}
      {!busy && result && (
        <>
          <VerdictBanner verdict={result.verdict} />
          <CheckList checks={result.checks} />
          <AnchorNote result={result} />
        </>
      )}
    </div>
  );
}

function AnchorNote({ result }: { result: VerifyResponse }) {
  if (!result.anchor) {
    return (
      <p className="note">
        Nothing was written to this case: an altered case is left exactly as found for investigation.
      </p>
    );
  }
  const { head_index, head_hash, timestamp_status, timestamp_gen_time } = result.anchor;
  return (
    <div className="note">
      <p>
        Recorded and anchored at custody entry {head_index}
        {timestamp_status === "granted" ? `, signed ${utc(timestamp_gen_time)}` : ", timestamp pending"}.
        Keep a copy of this hash outside this system; a later verification must still find it.
      </p>
      <p className="mono hash">{head_hash}</p>
    </div>
  );
}
