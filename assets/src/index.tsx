/* @refresh reload */
import { render } from "solid-js/web";
import { prewarmShareLandingPath } from "@/features/share";

prewarmShareLandingPath();

if ("serviceWorker" in navigator && import.meta.env.PROD) {
  const buildId = import.meta.env.VITE_APP_BUILD_ID ?? "dev";
  navigator.serviceWorker
    .register(`/sw.js?v=${encodeURIComponent(buildId)}`, { scope: "/" })
    .catch(() => {});
}

const root = document.getElementById("root");

void import("@/app/App").then(({ default: App }) => {
  render(() => <App />, root!);
});
