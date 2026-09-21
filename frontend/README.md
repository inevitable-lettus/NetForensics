# Frontend

Minimal React + TypeScript (Vite) page: upload a pcap, see the evidence seal and the
findings with their evidence strings, download the PDF report. The tamper-test /
integrity-verify view arrives with the evidence layer.

```
npm install
npm run dev      # http://localhost:5173, proxies /api to uvicorn on :8000
npm run build    # type-check + production build
```

API shapes in `src/types.ts` mirror `backend/models.py`.
