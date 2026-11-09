import type { Finding } from "../types";

function FindingRow({ finding, index }: { finding: Finding; index: number }) {
  const data = Object.entries(finding.supporting_data);
  return (
    <li className={`finding sev-${finding.severity}`} style={{ "--i": index } as React.CSSProperties}>
      <div className="finding-head">
        <span className="sev">{finding.severity}</span>
        <span className="mono finding-detector">{finding.detector}</span>
      </div>
      <p className="finding-what">{finding.what}</p>
      <p className="finding-evidence">{finding.evidence}</p>
      <p className="muted">{finding.why}</p>
      {data.length > 0 && (
        <details className="disclosure">
          <summary>Measured values</summary>
          <dl className="facts facts-compact">
            {data.map(([key, value]) => (
              <div key={key} className="row">
                <dt className="mono">{key}</dt>
                <dd className="mono">{String(value)}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </li>
  );
}

export function FindingsList({ findings, flowCount }: { findings: Finding[]; flowCount: number }) {
  if (findings.length === 0) {
    return (
      <div className="empty">
        <p className="empty-title">No detector fired</p>
        <p className="muted">
          {flowCount.toLocaleString("en-GB")} flows were checked for DNS exfiltration, C2 beaconing and
          port scanning. None crossed its threshold.
        </p>
      </div>
    );
  }
  return (
    <ol className="findings">
      {findings.map((finding, index) => <FindingRow key={index} finding={finding} index={index} />)}
    </ol>
  );
}
