import { reportUrl } from "../api";
import type { CaseRecord } from "../types";
import { FindingCard } from "./FindingCard";
import { SealPanel } from "./SealPanel";

export function CaseView({ record }: { record: CaseRecord }) {
  return (
    <div>
      <SealPanel seal={record.seal} />
      <section>
        <h2>
          Findings ({record.findings.length}){" "}
          <a className="button" href={reportUrl(record.case_id)} target="_blank" rel="noreferrer">
            PDF report
          </a>
        </h2>
        <p className="muted">{record.flow_count} flows analysed · case {record.case_id}</p>
        {record.findings.length === 0 && <p>No detector fired on this capture.</p>}
        {record.findings.map((finding, index) => (
          <FindingCard key={index} finding={finding} />
        ))}
      </section>
    </div>
  );
}
