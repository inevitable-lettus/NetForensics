import type { CheckResult, Verdict } from "./types";

/** Plain-language names for the five checks of backend/evidence/verify.py, in order. */
export const CHECK_LABELS: Record<string, { title: string; question: string }> = {
  pcap_digests: { title: "Evidence file", question: "Do the stored bytes still hash to the sealed BLAKE3 and SHA-256?" },
  custody_chain: { title: "Chain of custody", question: "Does every custody entry re-hash and link to the one before?" },
  seal_binding: { title: "Seal binding", question: "Does the first custody entry belong to this seal?" },
  rfc3161_timestamp: { title: "Trusted timestamp", question: "Does the timestamp authority's signature over the seal verify?" },
  chain_head_anchor: { title: "Chain-head anchor", question: "Is every anchored custody entry still present, unchanged?" },
};

export const checkTitle = (check: CheckResult): string => CHECK_LABELS[check.name]?.title ?? check.name;

export type CheckState = "pass" | "fail" | "pending";

export const checkState = (check: CheckResult): CheckState =>
  check.passed === true ? "pass" : check.passed === false ? "fail" : "pending";

export const STATE_LABEL: Record<CheckState, string> = { pass: "Passed", fail: "Failed", pending: "Not run" };

export const VERDICT_COPY: Record<Verdict, { label: string; summary: string }> = {
  intact: {
    label: "Verified",
    summary: "The stored evidence matches its seal, the custody record is unbroken and a timestamp authority vouches for both.",
  },
  altered: {
    label: "Altered",
    summary: "At least one check failed. The evidence or its custody record is not as it was sealed.",
  },
  incomplete: {
    label: "Incomplete",
    summary: "Nothing failed, but a trusted timestamp is still pending, so the result rests partly on this system's own clock.",
  },
};
