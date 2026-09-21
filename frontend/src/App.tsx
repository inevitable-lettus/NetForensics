import { useState } from "react";
import { uploadPcap } from "./api";
import { CaseView } from "./components/CaseView";
import { UploadForm } from "./components/UploadForm";
import type { CaseRecord } from "./types";

export default function App() {
  const [record, setRecord] = useState<CaseRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleFile(file: File) {
    setBusy(true);
    setError(null);
    try {
      setRecord(await uploadPcap(file));
    } catch (failure) {
      setRecord(null);
      setError(failure instanceof Error ? failure.message : "Upload failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <h1>NetForensics</h1>
      <p className="lede">
        Upload a capture. It is hashed and sealed before any analysis runs.
      </p>
      <UploadForm busy={busy} onFile={handleFile} />
      {error && <p role="alert" className="error">{error}</p>}
      {record && <CaseView record={record} />}
    </main>
  );
}
