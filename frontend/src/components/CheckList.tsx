import { checkState, checkTitle, CHECK_LABELS, STATE_LABEL } from "../checks";
import type { CheckResult } from "../types";
import { StatusMark } from "./StatusMark";

export function CheckList({ checks }: { checks: CheckResult[] }) {
  return (
    <ol className="checks">
      {checks.map((check, index) => {
        const state = checkState(check);
        return (
          <li key={check.name} className={`check check-${state}`} style={{ "--i": index } as React.CSSProperties}>
            <StatusMark state={state} />
            <div className="check-body">
              <div className="check-head">
                <span className="check-title">{checkTitle(check)}</span>
                <span className={`pill pill-${state}`}>{STATE_LABEL[state]}</span>
              </div>
              <p className="check-question muted">{CHECK_LABELS[check.name]?.question}</p>
              <p className="check-evidence">{check.evidence}</p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function CheckListSkeleton() {
  return (
    <ol className="checks" aria-busy="true" aria-label="Verifying">
      {Array.from({ length: 5 }, (_, index) => (
        <li key={index} className="check">
          <span className="skeleton skeleton-mark" />
          <div className="check-body">
            <span className="skeleton skeleton-line" style={{ width: "32%" }} />
            <span className="skeleton skeleton-line" style={{ width: "88%" }} />
            <span className="skeleton skeleton-line" style={{ width: "64%" }} />
          </div>
        </li>
      ))}
    </ol>
  );
}
