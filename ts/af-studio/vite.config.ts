import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Build into dist/ like the other TypeScript surfaces; tests run in jsdom so
// they exercise the real DOM output without a native server.
export default defineConfig({
  base: "/studio/",
  plugins: [react()],
  build: { outDir: "dist" },
  test: { environment: "jsdom" },
});
