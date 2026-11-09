import { useEffect, useState } from "react";
import { getCase, uploadPcap } from "./api";
import { CaseView } from "./components/CaseView";
import { OpenCaseForm } from "./components/OpenCaseForm";
import { SealPanel } from "./components/SealPanel";
import { UploadForm } from "./components/UploadForm";
import { caseFromHash, setCaseHash } from "./hashRoute";
import type { CaseRecord } from "./types";

const STEPS = [
  { title: "Seal", text: "The capture is hashed with BLAKE3 and SHA-256 the moment it arrives, before anything reads it." },
  { title: "Analyse", text: "Four rule-based detectors run. Every finding states the measured value and the threshold it crossed." },
  { title: "Verify", text: "Any time later, re-hash the stored copy and re-check the custody chain, timestamp and anchor." },
];

export default function App() {
  const [record, setRecord] = useState<CaseRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load(work: () => Promise<CaseRecord>, failureText: string) {
    setBusy(true);
    setError(null);
    try {
      const next = await work();
      setRecord(next);
      setCaseHash(next.case_id);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : failureText);
    } finally {
      setBusy(false);
    }
  }

  // Open the case named in the hash on first load, and again whenever the hash changes
  // in this tab (a pasted case link, a manual edit, back/forward).
  useEffect(() => {
    function openFromHash() {
      const caseId = caseFromHash();
      if (caseId) void load(() => getCase(caseId), "Could not open the case.");
      else if (window.location.hash === "") setRecord(null);
    }
    openFromHash();
    window.addEventListener("hashchange", openFromHash);
    return () => window.removeEventListener("hashchange", openFromHash);
  }, []);

  return (
    <div className="shell">
      <header className="topbar">
        <a className="brand" href="/" onClick={(event) => { event.preventDefault(); setRecord(null); setCaseHash(null); }}>
          <span className="brand-mark" aria-hidden="true" />
          NetForensics
        </a>
        <span className="topbar-tag">Packet forensics with a tamper-evident evidence record</span>
      </header>
      <div className={`layout${record ? " has-case" : ""}`}>
        <aside className="rail">
          <section className="panel" aria-labelledby="intake-title">
            <h2 id="intake-title" className="panel-title">New case</h2>
            <UploadForm busy={busy} onFile={(file) => load(() => uploadPcap(file), "Upload failed.")} />
            <OpenCaseForm busy={busy} onOpen={(caseId) => load(() => getCase(caseId), "Could not open the case.")} />
            {error && <p role="alert" className="inline-error">{error}</p>}
          </section>
          {record && <SealPanel seal={record.seal} />}
        </aside>
        <main className="main">
          {record ? (
            <CaseView key={record.case_id} record={record} />
          ) : busy ? (
            <div className="intro" aria-busy="true">
              <span className="skeleton skeleton-line" style={{ width: "40%", height: 28 }} />
              <span className="skeleton skeleton-line" style={{ width: "75%" }} />
              <span className="skeleton skeleton-line" style={{ width: "60%" }} />
            </div>
          ) : (
            <div className="intro">
              <p className="eyebrow">Evidence integrity first</p>
              <h1 className="intro-title">Seal a packet capture, analyse it, and prove later that nothing changed.</h1>
              <ol className="steps">
                {STEPS.map((step, index) => (
                  <li key={step.title} className="step" style={{ "--i": index } as React.CSSProperties}>
                    <span className="step-number mono">{String(index + 1).padStart(2, "0")}</span>
                    <div>
                      <p className="step-title">{step.title}</p>
                      <p className="muted">{step.text}</p>
                    </div>
                  </li>
                ))}
              </ol>
              <p className="muted intro-foot">
                Verified means the stored bytes match the seal and an independent timestamp vouches for
                them. It is designed toward admissibility, not a legal ruling.
              </p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
