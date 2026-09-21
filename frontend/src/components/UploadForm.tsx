import type { ChangeEvent } from "react";

interface Props {
  busy: boolean;
  onFile: (file: File) => void;
}

export function UploadForm({ busy, onFile }: Props) {
  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) onFile(file);
    event.target.value = ""; // allow re-uploading the same file
  }

  return (
    <label className="upload">
      <span>{busy ? "Sealing and analysing…" : "Choose a .pcap file"}</span>
      <input type="file" accept=".pcap,.cap" disabled={busy} onChange={handleChange} />
    </label>
  );
}
