# Frontend

React + TypeScript (Vite) page: upload a pcap or open a case by id, see the evidence
seal and the findings with their evidence strings, verify the case (five checks and the
verdict) and run the tamper test on a throwaway copy. The PDF report link is unchanged.

```
npm install
npm run dev      # http://localhost:5173, proxies /api to uvicorn on :8000 (or NF_API_URL)
npm run build    # type-check + production build
```

API shapes in `src/types.ts` mirror `backend/models.py`.
