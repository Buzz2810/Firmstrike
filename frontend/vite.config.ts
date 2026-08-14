import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";
import { fileURLToPath } from "node:url";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig(({ mode }) => {
  // Load environment variables from the frontend project root
  const env = loadEnv(mode, process.cwd(), "");

  const port = Number(env.VITE_PORT || env.PORT || 25439);

  if (Number.isNaN(port) || port <= 0) {
    throw new Error(
      `Invalid port value: ${env.VITE_PORT || env.PORT}`,
    );
  }

  const basePath = env.BASE_PATH || "/";

  return {
    base: basePath,

    plugins: [
      react(),
      tailwindcss(),
      runtimeErrorOverlay(),
    ],

    resolve: {
      alias: {
        "@": path.resolve(__dirname, "src"),

        "@workspace/api-client-react": path.resolve(
          __dirname,
          "api-client",
          "src",
          "index.ts",
        ),

        "@assets": path.resolve(
          __dirname,
          "..",
          "attached_assets",
        ),
      },

      dedupe: ["react", "react-dom"],
    },

    root: __dirname,

    build: {
      outDir: path.resolve(__dirname, "dist/public"),
      emptyOutDir: true,
    },

    server: {
      port,
      strictPort: true,
      host: "0.0.0.0",
      allowedHosts: true,

      fs: {
        strict: true,
      },

      proxy: {
        "/api/": {
          target:
            env.API_PROXY_TARGET ?? "http://localhost:8080",
          changeOrigin: true,
          timeout: 0,
          proxyTimeout: 0,
        },
      },
    },

    preview: {
      port,
      host: "0.0.0.0",
      allowedHosts: true,

      proxy: {
        "/api/": {
          target:
            env.API_PROXY_TARGET ?? "http://localhost:8080",
          changeOrigin: true,
          timeout: 0,
          proxyTimeout: 0,
        },
      },
    },
  };
});