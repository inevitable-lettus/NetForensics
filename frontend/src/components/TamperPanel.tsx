import { useState } from "react";
import { runTamperTest } from "../api";
import { checkState, checkTitle, STATE_LABEL } from "../checks";
import type { TamperTest } from "../types";
import { CheckListSkeleton } from "./CheckList";
import { StatusMark } from "./StatusMark";
import { VerdictBanner } from "./VerdictBanner";

export function TamperPanel({ caseId }: { caseId: string }) {
  const [result, setResult] = useState<TamperTest | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      setResult(await runTamperTest(caseId));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Tamper test failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <div className="toolbar">
        <p className="muted toolbar-text">
          Copies the stored capture to a throwaway file, verifies the copy, flips one bit in it and
          verifies again. The stored evidence and its custody chain are never changed.
        </p>
        <button type="button" className="btn btn-danger" onClick={run} disabled={busy}>
          {busy ? "Running" : result ? "Run again" : "Run tamper test"}
        </button>
      </div>
      {error && <p role="alert" className="inline-error">{error}</p>}
      {busy && <CheckListSkeleton />}
      {!busy && !result && !error && (
        <div className="empty">
          <p className="empty-title">One flipped bit is enough</p>
          <p className="muted">
            Changing a single bit of a capture changes both of its hashes completely. This test shows
            verification catching it.
          </p>
        </div>
      )}
      {!busy && result && <TamperResult result={result} />}
    </div>
  );
}

function TamperResult({ result }: { result: TamperTest }) {
  const failed = result.after.checks.filter((check) => check.passed === false);
  return (
    <>
      <div className="compare">
        <div>
          <p className="eyebrow">Copy as stored</p>
          <VerdictBanner verdict={result.before.verdict} compact />
        </div>
        <div>
          <p className="eyebrow">After flipping one bit of byte {result.flipped_offset.toLocaleString("en-GB")}</p>
          <VerdictBanner verdict={result.after.verdict} compact />
        </div>
      </div>
      <table className="table">
        <thead>
          <tr><th scope="col">Check</th><th scope="col">Before</th><th scope="col">After</th></tr>
        </thead>
        <tbody>
          {result.before.checks.map((check, index) => {
            const after = result.after.checks[index];
            return (
              <tr key={check.name}>
                <th scope="row">{checkTitle(check)}</th>
                <td><StateCell state={checkState(check)} /></td>
                <td><StateCell state={checkState(after)} /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {failed.map((check) => (
        <div key={check.name} className="note note-fail">
          <p className="note-title">{checkTitle(check)}</p>
          <p className="mono hash">{check.evidence}</p>
        </div>
      ))}
    </>
  );
}

function StateCell({ state }: { state: ReturnType<typeof checkState> }) {
  return <span className="state-cell"><StatusMark state={state} />{STATE_LABEL[state]}</span>;
}
