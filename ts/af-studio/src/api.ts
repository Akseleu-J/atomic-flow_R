/** Typed bridge between the studio UI and the validated af-client.
 *  Plain functions only: no router, no state library — hooks stay in App.tsx. */
import {
  AfClient,
  AfHttpError,
  AfProtocolError,
  AfTransportError,
  WireError,
  type BudgetSnapshotDto,
  type ChatEvent,
  type ChatInput,
  type GraphReadDto,
  type HealthDto,
  type SessionCreated,
  type SessionListDto,
  type SessionSummaryDto,
} from "@atomic-flow/af-client";

/** Native af serve loopback endpoint; the studio never talks to third-party hosts. */
export const DEFAULT_BASE_URL = window.location.origin;

export interface StudioConfig { baseUrl: string; token?: string }

export function createStudioClient(config: StudioConfig): AfClient {
  return new AfClient(config);
}

export type StudioErrorKind = "http" | "wire" | "transport" | "unknown";
export interface StudioError { status: "error"; kind: StudioErrorKind; message: string }
export type StudioResult<T> = { status: "ok"; value: T } | StudioError;

/** Classified failure; the UI renders it verbatim and never retries on its own. */
function failure(error: unknown): StudioError {
  if (error instanceof AfHttpError) return { status: "error", kind: "http", message: `af serve HTTP ${error.status}` };
  if (error instanceof WireError || error instanceof AfProtocolError) return { status: "error", kind: "wire", message: error.message };
  if (error instanceof AfTransportError) return { status: "error", kind: "transport", message: "исход операции неизвестен; проверьте журнал и бюджет host перед продолжением" };
  return { status: "error", kind: "unknown", message: error instanceof Error ? error.message : "неизвестный отказ" };
}

export async function guard<T>(run: () => Promise<T>): Promise<StudioResult<T>> {
  try { return { status: "ok", value: await run() }; } catch (error) { return failure(error); }
}

export const studioApi = {
  health: (client: AfClient): Promise<StudioResult<HealthDto>> => guard(() => client.health()),
  sessions: (client: AfClient): Promise<StudioResult<SessionListDto>> => guard(() => client.listSessions()),
  session: (client: AfClient, sessionId: string): Promise<StudioResult<SessionSummaryDto>> => guard(() => client.readSession(sessionId)),
  budget: (client: AfClient): Promise<StudioResult<BudgetSnapshotDto>> => guard(() => client.readBudget()),
  graph: (client: AfClient, rootId: string): Promise<StudioResult<GraphReadDto>> => guard(() => client.readGraph(rootId)),
  createSession: (client: AfClient, rootId?: string): Promise<StudioResult<SessionCreated>> => guard(() => client.createSession(undefined, rootId)),
};

/** Single bounded SSE stream. An explicit abort maps to "stopped"; nothing
 *  ever replays a model call or auto-resubmits after an unknown outcome. */
export async function streamChat(
  client: AfClient,
  input: ChatInput,
  onEvent: (event: ChatEvent) => void,
  signal?: AbortSignal,
): Promise<StudioResult<null> | { status: "stopped" }> {
  try {
    for await (const event of client.chat(input, signal === undefined ? {} : { signal })) onEvent(event);
    return { status: "ok", value: null };
  } catch (error) {
    if (signal?.aborted) return { status: "stopped" };
    return failure(error);
  }
}
