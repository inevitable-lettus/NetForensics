import { useState, type ChangeEvent, type DragEvent } from "react";
import { UploadIcon } from "./Icons";

interface Props {
  busy: boolean;
  onFile: (file: File) => void;
}

export function UploadForm({ busy, onFile }: Props) {
  const [over, setOver] = useState(false);

  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) onFile(file);
    event.target.value = ""; // allow re-uploading the same file
  }

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setOver(false);
    const file = event.dataTransfer.files?.[0];
    if (file && !busy) onFile(file);
  }

  return (
    <label
      className={`dropzone${over ? " is-over" : ""}${busy ? " is-busy" : ""}`}
      onDragOver={(event) => { event.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={handleDrop}
    >
      <UploadIcon className="dropzone-icon" />
      <span className="dropzone-title">{busy ? "Sealing and analysing" : "Drop a capture or choose a file"}</span>
      <span className="dropzone-hint">.pcap or .cap, hashed and sealed before any analysis runs</span>
      <input type="file" accept=".pcap,.cap" disabled={busy} onChange={handleChange} />
    </label>
  );
}
