/** Entry point. Plain Vite React app: no router, no state library. */
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import "./styles.css";

const mount = document.getElementById("root");
if (mount === null) throw new Error("#root element is missing; cannot mount the studio");
createRoot(mount).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
