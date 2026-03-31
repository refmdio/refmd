/* @refresh reload */
import { render } from "solid-js/web";
import App from "./app";

if ("serviceWorker" in navigator && import.meta.env.PROD) {
  navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {});
}

const root = document.getElementById("root");

render(() => <App />, root!);
