import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";

export default defineConfig(async ({ mode }) => {
  // Load environment variables from the project root
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
      ...(process.env.NODE_ENV !== "production" &&
      process.env.REPL_ID !== undefined
        ? [
            (await import("@replit/vite-plugin-cartographer")).cartographer({
              root: path.resolve(import.meta.dirname, ".."),
            }),
            (await import("@replit/vite-plugin-dev-banner")).devBanner(),
          ]
        : []),
    ],

    resolve: {
      alias: {
        "@": path.resolve(import.meta.dirname, "src"),
        "@assets": path.resolve(
          import.meta.dirname,
          "..",
          "..",
          "attached_assets",
        ),
      },
      dedupe: ["react", "react-dom"],
    },

    root: path.resolve(import.meta.dirname),

    build: {
      outDir: path.resolve(import.meta.dirname, "dist/public"),
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
        "/api": {
          target: env.API_PROXY_TARGET ?? "http://localhost:8080",
          changeOrigin: true,
        },
      },
    },

    preview: {
      port,
      host: "0.0.0.0",
      allowedHosts: true,
      proxy: {
        "/api": {
          target: env.API_PROXY_TARGET ?? "http://localhost:8080",
          changeOrigin: true,
        },
      },
    },
  };
});