import type { CaseRecord } from "./types";

export async function uploadPcap(file: File): Promise<CaseRecord> {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch("/api/cases", { method: "POST", body });
  if (!response.ok) {
    const problem = await response.json().catch(() => null);
    throw new Error(problem?.detail ?? `Upload failed (HTTP ${response.status})`);
  }
  return response.json();
}

export const reportUrl = (caseId: string): string => `/api/cases/${caseId}/report.pdf`;
