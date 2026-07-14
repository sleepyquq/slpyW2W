import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.jsx";
import "./styles.css";

if (import.meta.env.VITE_PYXIS_BUILD === "true") {
  document.title = "slpyW2W - Pyxis VPN";
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
