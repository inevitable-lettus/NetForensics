import { useState } from "react";
import { reportUrl } from "../api";
import type { CaseRecord } from "../types";
import { FindingsList } from "./FindingsList";
import { FileIcon } from "./Icons";
import { TamperPanel } from "./TamperPanel";
import { VerifyPanel } from "./VerifyPanel";

type Tab = "findings" | "verify" | "tamper";
const TABS: { id: Tab; label: string }[] = [
  { id: "findings", label: "Findings" },
  { id: "verify", label: "Verification" },
  { id: "tamper", label: "Tamper test" },
];

export function CaseView({ record }: { record: CaseRecord }) {
  const [tab, setTab] = useState<Tab>("findings");
  return (
    <section className="case" aria-labelledby="case-title">
      <header className="case-header">
        <div>
          <p className="eyebrow">Case <span className="mono">{record.case_id}</span></p>
          <h1 id="case-title" className="case-title">{record.seal.pcap_filename}</h1>
          <p className="muted">
            {record.flow_count.toLocaleString("en-GB")} {record.flow_count === 1 ? "flow" : "flows"} analysed · {record.findings.length}{" "}
            {record.findings.length === 1 ? "finding" : "findings"}
          </p>
        </div>
        <a className="btn btn-secondary" href={reportUrl(record.case_id)} target="_blank" rel="noreferrer">
          <FileIcon /> PDF report
        </a>
      </header>
      <div className="tabs" role="tablist" aria-label="Case views">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            role="tab"
            id={`tab-${id}`}
            aria-selected={tab === id}
            aria-controls={`panel-${id}`}
            className="tab"
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>
      {/* Panels stay mounted so a result survives switching tabs. */}
      <div role="tabpanel" id="panel-findings" aria-labelledby="tab-findings" hidden={tab !== "findings"}>
        <FindingsList findings={record.findings} flowCount={record.flow_count} />
      </div>
      <div role="tabpanel" id="panel-verify" aria-labelledby="tab-verify" hidden={tab !== "verify"}>
        <VerifyPanel caseId={record.case_id} />
      </div>
      <div role="tabpanel" id="panel-tamper" aria-labelledby="tab-tamper" hidden={tab !== "tamper"}>
        <TamperPanel caseId={record.case_id} />
      </div>
    </section>
  );
}
