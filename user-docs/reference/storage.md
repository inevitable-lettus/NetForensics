# Storage layout

Everything a case needs lives under one **store directory**: `evidence_store/` in the current
directory by default, or whatever `--store` names. Back up the whole directory; move it
as a unit.

```text
evidence_store/
├── netforensics.sqlite      cases, seals, findings, custody entries, anchors
├── blobs/
│   └── <sha256>             the stored capture, named by its own SHA-256, read-only
└── staging/
    └── <case-id>/           a capture is staged here while it is validated and sealed
```

## Database tables

| Table | Holds |
|---|---|
| `cases` | One row per case: case id, flow count, creation time. |
| `seals` | The seal: file name and size, both hashes, received time, timestamp status (`pending` or `granted`), the stored token, its time and the authority URL. |
| `findings` | The findings of each case, in order: detector, what, why, supporting data, evidence sentence, severity. |
| `custody_entries` | The hash-chained custody log, one row per event: index, time, event type, detail, previous hash, entry hash, payload. |
| `chain_anchors` | The timestamped chain heads: head index and hash, time, timestamp status, token. |

## How it is protected

- **Append-only.** Triggers refuse every `UPDATE` and `DELETE`, and any `INSERT` whose key
  already exists (this closes `INSERT OR REPLACE`). The one allowed change: a seal's timestamp
  going from `PENDING` to `GRANTED`, once, with a non-empty token.
- **Content-addressed captures.** A capture is stored under its own SHA-256. The store
  re-computes the hash of the staged file and refuses to store it under any other name. If a
  blob with that name already exists (the same evidence twice), it is re-hashed first and the
  store refuses loudly if it was altered.
- **Read-only blobs.** Stored captures are made read-only.
- **All or nothing.** A case, its seal and its findings are written in one transaction.

## What this does not protect against

The triggers stop mistakes in the program. Someone who can write the `.sqlite` file can drop
a trigger or edit bytes. The custody chain and the timestamped anchors are what catch that,
which is why [`verify`](../guide/verify.md) matters and why you should keep the `Anchor` line
it prints somewhere else.

## Two cases, one capture

Sealing the same bytes twice makes two cases that share one `blobs/<sha256>` file.
That is why [`tamper-demo`](../guide/tamper-demo.md) always uses a throwaway store: damaging
the shared file would damage both cases.
