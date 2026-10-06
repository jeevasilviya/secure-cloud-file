import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiProxyTarget = env.API_PROXY_TARGET || "http://127.0.0.1:8000";
  const apiRoutes = [
    "/register",
    "/login",
    "/logout",
    "/profile",
    "/upload",
    "/files",
    "/download",
    "/health",
  ];

  return {
    plugins: [react()],
    server: {
      host: "127.0.0.1",
      port: 5173,
      proxy: Object.fromEntries(
        apiRoutes.map((route) => [
          route,
          { target: apiProxyTarget, changeOrigin: true },
        ]),
      ),
    },
  };
});
