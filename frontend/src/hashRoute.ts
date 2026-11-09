/** The open case lives in the URL hash (#case=<id>) so a reload or a shared link reopens it. */
export function caseFromHash(): string | null {
  const match = window.location.hash.match(/^#case=([0-9a-f]{32})$/);
  return match ? match[1] : null;
}

export function setCaseHash(caseId: string | null): void {
  window.history.replaceState(null, "", caseId ? `#case=${caseId}` : window.location.pathname);
}
