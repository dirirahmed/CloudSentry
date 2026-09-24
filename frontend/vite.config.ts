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

export default defineConfig({
  plugins: [react()],
  server: { proxy: apiProxy },
  preview: { proxy: apiProxy },
  test: { environment: "jsdom" },
});
