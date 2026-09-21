import type { Finding } from "../types";

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className={`finding sev-${finding.severity}`}>
      <header>
        <span className="badge">{finding.severity}</span>
        <strong>{finding.detector}</strong>
        <span>{finding.what}</span>
      </header>
      <p className="evidence">{finding.evidence}</p>
      <p>{finding.why}</p>
      <details>
        <summary>Supporting data</summary>
        <dl>
          {Object.entries(finding.supporting_data).map(([key, value]) => (
            <div key={key} className="row">
              <dt>{key}</dt>
              <dd>{String(value)}</dd>
            </div>
          ))}
        </dl>
      </details>
    </article>
  );
}
