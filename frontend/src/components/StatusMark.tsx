import type { CheckState } from "../checks";
import { CheckIcon, ClockIcon, CrossIcon } from "./Icons";

/** A coloured round mark for one check state. Pending is amber, never green. */
export function StatusMark({ state }: { state: CheckState }) {
  const Icon = state === "pass" ? CheckIcon : state === "fail" ? CrossIcon : ClockIcon;
  return (
    <span className={`mark mark-${state}`}>
      <Icon />
    </span>
  );
}
