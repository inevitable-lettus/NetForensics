import { useState, type FormEvent } from "react";

interface Props {
  busy: boolean;
  onOpen: (caseId: string) => void;
}

const CASE_ID = /^[0-9a-f]{32}$/;

export function OpenCaseForm({ busy, onOpen }: Props) {
  const [value, setValue] = useState("");
  const [problem, setProblem] = useState<string | null>(null);

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    const caseId = value.trim().toLowerCase();
    if (!CASE_ID.test(caseId)) {
      setProblem("A case id is 32 hexadecimal characters.");
      return;
    }
    setProblem(null);
    onOpen(caseId);
  }

  return (
    <form className="field" onSubmit={handleSubmit} noValidate>
      <label htmlFor="case-id">Open an existing case</label>
      <div className="field-row">
        <input
          id="case-id"
          className="mono"
          placeholder="Case id"
          value={value}
          spellCheck={false}
          autoComplete="off"
          onChange={(event) => setValue(event.target.value)}
          aria-invalid={problem !== null}
          aria-describedby="case-id-help"
        />
        <button type="submit" className="btn btn-secondary" disabled={busy}>Open</button>
      </div>
      <p id="case-id-help" className={problem ? "field-error" : "field-help"}>
        {problem ?? "Printed by the upload and by python -m backend.cli seal."}
      </p>
    </form>
  );
}
