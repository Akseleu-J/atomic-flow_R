import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const api = vi.hoisted(() => ({
  make: vi.fn(() => ({})),
  health: vi.fn(async () => ({ status: "ok", value: { version: "test" } })),
  budget: vi.fn(async () => ({ status: "ok", value: { state: "missing" } })),
  sessions: vi.fn(async () => ({ status: "ok", value: { sessions: [] } })),
  graph: vi.fn(),
  createSession: vi.fn(),
  chat: vi.fn(async () => ({ status: "ok", value: null })),
}));
vi.mock("./api", () => ({
  createStudioClient: api.make,
  DEFAULT_BASE_URL: window.location.origin,
  studioApi: api,
  streamChat: api.chat,
}));

describe("Studio request boundaries", () => {
  let container: HTMLDivElement;
  let root: Root;
  beforeEach(async () => {
    Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
    vi.clearAllMocks();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 404 })));
    container = document.createElement("div");
    document.body.append(container);
    root = createRoot(container);
    await act(async () => root.render(<App />));
  });
  afterEach(async () => {
    await act(async () => root.unmount());
    container.remove();
    vi.unstubAllGlobals();
  });

  function input(element: HTMLInputElement | HTMLTextAreaElement, value: string): void {
    const proto = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true }));
  }

  it("sends credentials through the same-origin client and clears the input", async () => {
    await act(async () => input(container.querySelector("#studio-token")!, "fixture-token"));
    await act(async () => container.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    expect(api.make).toHaveBeenLastCalledWith({ baseUrl: window.location.origin, token: "fixture-token" });
    expect(container.querySelector<HTMLInputElement>("#studio-token")?.value).toBe("");
  });

  it("admits only one send while session creation is pending", async () => {
    let resolve!: (result: unknown) => void;
    api.createSession.mockImplementation(() => new Promise(done => { resolve = done; }));
    const textarea = container.querySelector<HTMLTextAreaElement>("textarea")!;
    await act(async () => input(textarea, "fixture question"));
    await act(async () => {
      textarea.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      textarea.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    });
    expect(api.createSession).toHaveBeenCalledTimes(1);
    expect(container.querySelector<HTMLInputElement>(".root-input")?.disabled).toBe(true);
    await act(async () => resolve({ status: "ok", value: { session_id: "fixture" } }));
    expect(api.chat).toHaveBeenCalledTimes(1);
  });

  it("discards a graph response from a previous project", async () => {
    let resolve!: (result: unknown) => void;
    api.graph.mockImplementation(() => new Promise(done => { resolve = done; }));
    const field = container.querySelector<HTMLInputElement>(".root-input")!;
    await act(async () => input(field, "old-root"));
    await act(async () => container.querySelector<HTMLButtonElement>(".mini-btn")!.click());
    await act(async () => input(field, "new-root"));
    await act(async () => resolve({ status: "ok", value: { files: [{ path: "stale.txt", layer: "resource", symbols: [] }] } }));
    expect(container.textContent).not.toContain("stale.txt");
  });

  it("keeps reviewed edit unavailable when the server has no profile", () => {
    expect(container.textContent).toContain("Профиль правки доступен");
    expect(container.querySelector("#studio-replacement")).toBeNull();
  });

  it("submits a reviewed replacement once in a session bound to the profile", async () => {
    const hash = "a".repeat(64);
    const json = (body: unknown): Response => new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
    const request = vi.fn()
      .mockResolvedValueOnce(json({
        schema_version: 1, root_id: "approved-root", file: "src/lib.rs",
        before_sha256: hash, replacement_sha256: hash, requirement_id: "check-1",
      }))
      .mockResolvedValueOnce(json({
        schema_version: 1, status: "published", published: true, evidence_sha256: hash, publication: {},
      }));
    vi.stubGlobal("fetch", request);
    api.createSession.mockResolvedValueOnce({ status: "ok", value: { session_id: "review-session" } });
    await act(async () => container.querySelector("header form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    const textarea = container.querySelector<HTMLTextAreaElement>("#studio-replacement")!;
    await act(async () => input(textarea, "reviewed bytes"));
    const form = textarea.closest("form")!;
    await act(async () => {
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    expect(api.createSession).toHaveBeenCalledTimes(1);
    expect(api.createSession).toHaveBeenCalledWith(expect.anything(), "approved-root");
    expect(request).toHaveBeenCalledTimes(2);
    expect(request.mock.calls[1]?.[0]).toBe("/v1/reviewed-edit");
    expect(JSON.parse(request.mock.calls[1]?.[1].body)).toEqual({ session_id: "review-session", replacement: "reviewed bytes" });
    expect(container.querySelector(".reviewed-edit [role=status]")?.textContent).toContain("Правка опубликована");
    expect(textarea.value).toBe("");
  });
});
