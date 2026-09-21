// Mirrors backend/models.py as serialised by backend/db/serialization.py.

export type Severity = "info" | "low" | "medium" | "high";
export type TimestampStatus = "granted" | "pending";

export interface Seal {
  pcap_filename: string;
  pcap_size_bytes: number;
  hash_algorithm: string;
  pcap_hash: string;
  sha256_hash: string;
  received_at: string;
  timestamp_status: TimestampStatus;
  rfc3161_token: string | null;
  timestamp_gen_time: string | null;
  tsa_url: string | null;
}

export interface Finding {
  detector: string;
  what: string;
  why: string;
  supporting_data: Record<string, string | number | boolean | null>;
  evidence: string;
  severity: Severity;
}

export interface CaseRecord {
  case_id: string;
  seal: Seal;
  findings: Finding[];
  flow_count: number;
}
