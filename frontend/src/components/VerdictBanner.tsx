import { VERDICT_COPY } from "../checks";
import type { Verdict } from "../types";
import { CheckIcon, ClockIcon, CrossIcon } from "./Icons";

export function VerdictBanner({ verdict, compact = false }: { verdict: Verdict; compact?: boolean }) {
  const copy = VERDICT_COPY[verdict];
  const Icon = verdict === "intact" ? CheckIcon : verdict === "altered" ? CrossIcon : ClockIcon;
  return (
    <div className={`verdict verdict-${verdict}${compact ? " verdict-compact" : ""}`} role="status">
      <span className="verdict-icon"><Icon /></span>
      <div>
        <p className="verdict-label">{copy.label}</p>
        {!compact && <p className="verdict-summary">{copy.summary}</p>}
      </div>
    </div>
  );
}
