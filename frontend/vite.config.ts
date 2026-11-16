/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The browser calls /api/*; Vite forwards it to the local FastAPI server with the /api prefix removed.
// This keeps the dashboard and API on one origin, so the backend needs no CORS configuration.
const apiProxy = {
  "/api": {
    target: "http://127.0.0.1:8000",
    changeOrigin: true,
    rewrite: (path: string) => path.replace(/^\/api/, ""),
  },
};

// Listen on 127.0.0.1 explicitly: on some Windows machines "localhost" resolves to an address
// the browser cannot reach, and the page times out.
export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", proxy: apiProxy },
  preview: { host: "127.0.0.1", proxy: apiProxy },
  test: { environment: "jsdom" },
});
