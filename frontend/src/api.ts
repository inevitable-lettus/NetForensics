import type { CaseRecord, TamperTest, VerifyResponse } from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    const problem = await response.json().catch(() => null);
    throw new Error(problem?.detail ?? `Request failed (HTTP ${response.status})`);
  }
  return response.json();
}

export function uploadPcap(file: File): Promise<CaseRecord> {
  const body = new FormData();
  body.append("file", file);
  return request("/api/cases", { method: "POST", body });
}

export const getCase = (caseId: string): Promise<CaseRecord> =>
  request(`/api/cases/${encodeURIComponent(caseId)}`);

export const verifyCase = (caseId: string): Promise<VerifyResponse> =>
  request(`/api/cases/${encodeURIComponent(caseId)}/verify`, { method: "POST" });

export const runTamperTest = (caseId: string): Promise<TamperTest> =>
  request(`/api/cases/${encodeURIComponent(caseId)}/tamper-test`, { method: "POST" });

export const reportUrl = (caseId: string): string => `/api/cases/${caseId}/report.pdf`;
