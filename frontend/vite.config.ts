import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

declare const process: { env: Record<string, string | undefined> };

// Dev: proxy /api to the FastAPI server (uvicorn backend.api.app:app, port 8000)
// so the browser sees one origin and no CORS config is needed. NF_API_URL points
// the proxy at another address, e.g. when port 8000 is taken.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": process.env.NF_API_URL ?? "http://127.0.0.1:8000" } },
});
