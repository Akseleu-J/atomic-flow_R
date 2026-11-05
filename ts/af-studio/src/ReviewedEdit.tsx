import { useEffect, useRef, useState, type ReactElement } from "react";
import { AfProtocolError, type AfClient } from "@atomic-flow/af-client";
import { studioApi } from "./api";

interface Profile {
  root_id: string;
  file: string;
  before_sha256: string;
  replacement_sha256: string;
  requirement_id: string;
}

const SHA256 = /^[a-f0-9]{64}$/;
const HTTP_ERROR: Readonly<Record<number, string>> = {
  400: "Текст не совпадает с согласованной заменой.",
  401: "Подключите токен сервера.",
  404: "Профиль правки недоступен.",
  409: "Профиль, исходник или состояние сессии изменились. Проверьте журнал.",
  429: "Сервер уже выполняет правку.",
};

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AfProtocolError("Некорректный отчёт правки.");
  }
  return value as Record<string, unknown>;
}

function label(value: unknown, limit: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > limit || /[\x00-\x1f\x7f]/.test(value)) {
    throw new AfProtocolError("Некорректное поле профиля правки.");
  }
  return value;
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  if (!response.body || !response.headers.get("content-type")?.startsWith("application/json")) {
    throw new AfProtocolError("Сервер не вернул JSON отчёта.");
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let bytes = 0;
  let json = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 32_768) {
        await reader.cancel();
        throw new AfProtocolError("Отчёт превышает лимит размера.");
      }
      json += decoder.decode(value, { stream: true });
    }
    const result = object(JSON.parse(json + decoder.decode()));
    if (result.schema_version !== 1) throw new AfProtocolError("Версия отчёта недоступна.");
    return result;
  } finally {
    reader.releaseLock();
  }
}

function parseProfile(body: Record<string, unknown>): Profile {
  const before = label(body.before_sha256, 64);
  const replacement = label(body.replacement_sha256, 64);
  if (!SHA256.test(before) || !SHA256.test(replacement)) {
    throw new AfProtocolError("Некорректный SHA-256 профиля.");
  }
  return {
    root_id: label(body.root_id, 80),
    file: label(body.file, 1024),
    before_sha256: before,
    replacement_sha256: replacement,
    requirement_id: label(body.requirement_id, 256),
  };
}

function request(token: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch("/v1/reviewed-edit", { ...init, headers, redirect: "error", credentials: "same-origin", cache: "no-store" });
}

export function ReviewedEdit({ client, token, connected, blocked, setBusy }: {
  client: AfClient;
  token: string;
  connected: boolean;
  blocked: boolean;
  setBusy: (busy: boolean) => void;
}): ReactElement {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [replacement, setReplacement] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setLocalBusy] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const lock = useRef(false);
  useEffect(() => {
    if (!connected) return;
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await request(token, { signal: controller.signal });
        if (response.status === 404) return;
        if (!response.ok) throw new Error();
        const configured = parseProfile(await readJson(response));
        if (!controller.signal.aborted) setProfile(configured);
      } catch {
        if (!controller.signal.aborted) setMessage("Не удалось прочитать профиль правки.");
      }
    })();
    return () => controller.abort();
  }, [connected, token]);

  const submit = async (): Promise<void> => {
    if (!profile || blocked || lock.current || submitted || replacement === "") return;
    if (new TextEncoder().encode(replacement).byteLength > 512 * 1024) {
      setMessage("Размер замены превышает 512 КиБ.");
      return;
    }
    lock.current = true;
    setBusy(true);
    setLocalBusy(true);
    setMessage("");
    let sessionId: string | undefined;
    try {
      const session = await studioApi.createSession(client, profile.root_id);
      if (session.status === "error") {
        setMessage(`Не удалось открыть сессию правки. ${session.message}`);
        return;
      }
      sessionId = session.value.session_id;
      setSubmitted(true);
      const response = await request(token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sessionId, replacement }),
        signal: AbortSignal.timeout(120_000),
      });
      if (!response.ok) {
        const reason = HTTP_ERROR[response.status];
        setMessage(reason ? `${reason} Сессия ${sessionId}.` : `Исход правки неизвестен. Проверьте сессию ${sessionId}.`);
        return;
      }
      const result = await readJson(response);
      if (result.status === "published" && result.published === true &&
          typeof result.evidence_sha256 === "string" && SHA256.test(result.evidence_sha256)) {
        setReplacement("");
        setMessage(`Правка опубликована. Сессия ${sessionId}. SHA-256 доказательства ${result.evidence_sha256}.`);
      } else if (result.status === "refused" && result.published === false) {
        setMessage(`Правка отклонена. Проверьте сессию ${sessionId}.`);
      } else {
        setMessage(`Исход правки требует сверки. Проверьте сессию ${sessionId}.`);
      }
    } catch {
      setMessage(sessionId === undefined ? "Не удалось открыть сессию правки."
        : `Исход правки неизвестен. Проверьте сессию ${sessionId}.`);
    } finally {
      lock.current = false;
      setBusy(false);
      setLocalBusy(false);
    }
  };

  return <section className="reviewed-edit" aria-label="Согласованная правка">
    <h2>Согласованная правка</h2>
    {profile === null ? <p>{message || "Профиль правки доступен после настройки на сервере."}</p> :
      <form onSubmit={event => { event.preventDefault(); void submit(); }}>
        <dl>
          <dt>Проект</dt><dd>{profile.root_id}</dd>
          <dt>Файл</dt><dd>{profile.file}</dd>
          <dt>Требование</dt><dd>{profile.requirement_id}</dd>
          <dt>Исходный SHA-256</dt><dd className="mono">{profile.before_sha256}</dd>
          <dt>SHA-256 замены</dt><dd className="mono">{profile.replacement_sha256}</dd>
        </dl>
        <label htmlFor="studio-replacement">Согласованный текст замены</label>
        <textarea id="studio-replacement" value={replacement} maxLength={512 * 1024}
          disabled={busy || submitted} onChange={event => setReplacement(event.target.value)} rows={4} />
        <button className="v-btn" type="submit" disabled={busy || blocked || submitted || replacement === ""}>
          {busy ? "Выполняется проверка…" : "Проверить и применить"}
        </button>
        <p role="status">{message}</p>
      </form>}
  </section>;
}
