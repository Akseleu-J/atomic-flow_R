/** Atomic Flow Studio — bounded three-zone React surface.
 *  Zone 1: navigation rail + Context Explorer tree (af-client graph read).
 *  Zone 2: Workspace dialog streamed over af-client SSE + Ask/Edit/Task composer.
 *  Zone 3: Verification Summary fed by af-client evidence types.
 *  Every absent API renders an honest waiting note — never a stub or a fake. */
import { useEffect, useMemo, useRef, useState, type ReactElement } from "react";
import {
  type Assessment,
  type BudgetSnapshotDto,
  type ChatEvent,
  type GraphFileDto,
  type HealthDto,
  type SessionListDto,
  type VerificationReport,
} from "@atomic-flow/af-client";
import { createStudioClient, DEFAULT_BASE_URL, studioApi, streamChat, type StudioResult } from "./api";

import { ReviewedEdit } from "./ReviewedEdit";

type CheckKey = "identifier_hygiene" | "citation_validity" | "syntax" | "tests" | "requirements" | "model_critique";
const CHECKS: ReadonlyArray<readonly [CheckKey, string]> = [
  ["identifier_hygiene", "Идентификаторы"],
  ["citation_validity", "Цитаты"],
  ["syntax", "Синтаксис"],
  ["tests", "Тесты"],
  ["requirements", "Требования"],
  ["model_critique", "Критика модели"],
];
const STATUS_LABEL: Record<Assessment, string> = {
  not_assessed: "не оценено",
  not_applicable: "неприменимо",
  passed: "пройдено",
  failed: "провалено",
  unavailable: "недоступно",
};
const PUBLICATION_LABEL: Record<VerificationReport["publication"], string> = {
  not_requested: "публикация не запрошена",
  not_authorized: "публикация не авторизована",
  pending: "публикация ожидает",
  published: "опубликовано",
  failed: "публикация не удалась",
  unknown: "публикация неизвестна",
};

interface DialogMessage { kind: "user" | "assistant" | "error"; text: string; report?: VerificationReport }

function pluralFiles(count: number): string {
  const small = count % 10, mid = count % 100;
  const word = small === 1 && mid !== 11 ? "файл" : small >= 2 && small <= 4 && (mid < 12 || mid > 14) ? "файла" : "файлов";
  return `${count} ${word}`;
}
/** Mirrors the dashboard budget line: holds and unreadable ledgers stay visible. */
function budgetLine(budget: StudioResult<BudgetSnapshotDto> | null): string {
  if (budget === null) return "—";
  if (budget.status !== "ok") return "недоступен";
  const snapshot = budget.value;
  if (snapshot.state === "missing") return "не задан";
  if (snapshot.state === "unreadable") return "недоступен";
  if (snapshot.state === "hold") return "HOLD · нужна сверка";
  if ("committed_usd" in snapshot) return `$${snapshot.committed_usd} / $${snapshot.cap_usd}`;
  return "недоступен";
}

export function App(): ReactElement {
  const [connection, setConnection] = useState({ token: "", epoch: 0 });
  return <Workspace key={connection.epoch} token={connection.token} connect={token => {
    setConnection(previous => ({ token, epoch: previous.epoch + 1 }));
  }} />;
}

function Workspace({ token, connect }: { token: string; connect: (token: string) => void }): ReactElement {
  const client = useMemo(() => createStudioClient({ baseUrl: DEFAULT_BASE_URL, ...(token ? { token } : {}) }), [token]);
  const [tokenDraft, setTokenDraft] = useState("");
  const [reviewBusy, setReviewBusy] = useState(false);
  const [health, setHealth] = useState<StudioResult<HealthDto> | null>(null);
  const [budget, setBudget] = useState<StudioResult<BudgetSnapshotDto> | null>(null);
  const [sessions, setSessions] = useState<StudioResult<SessionListDto> | null>(null);
  const [rootId, setRootId] = useState("");
  const [graph, setGraph] = useState<StudioResult<GraphFileDto[]> | null>(null);
  const [messages, setMessages] = useState<DialogMessage[]>([]);
  const [streamText, setStreamText] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [composer, setComposer] = useState("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const graphRequest = useRef(0);
  useEffect(() => () => { abortRef.current?.abort(); graphRequest.current++; }, []);

  // Single warm-up pass: health, budget, durable session count. No polling,
  // no retry loop — failures stay visible in the status bar and rail badge.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const loadedHealth = await studioApi.health(client);
      if (cancelled) return;
      setHealth(loadedHealth);
      const loadedBudget = await studioApi.budget(client);
      if (cancelled) return;
      setBudget(loadedBudget);
      const loadedSessions = await studioApi.sessions(client);
      if (!cancelled) setSessions(loadedSessions);
    })();
    return () => { cancelled = true; };
  }, [client]);

  const loadGraph = async (): Promise<void> => {
    const request = ++graphRequest.current;
    const result = await studioApi.graph(client, rootId.trim());
    if (graphRequest.current !== request) return;
    setGraph(result.status === "ok" ? { status: "ok", value: result.value.files } : result);
  };

  const send = async (): Promise<void> => {
    const prompt = composer.trim();
    if (abortRef.current || reviewBusy || prompt === "" || health?.status !== "ok") return;
    const controller = new AbortController();
    abortRef.current = controller;
    setStreaming(true);
    setStreamText("");
    setReport(null);
    const trimmedRoot = rootId.trim();
    setComposer("");
    setMessages(previous => [...previous, { kind: "user", text: prompt }]);
    let sid = sessionId;
    if (sid === null) {
      const created = await studioApi.createSession(client, trimmedRoot === "" ? undefined : trimmedRoot);
      if (controller.signal.aborted || created.status !== "ok") {
        abortRef.current = null;
        setStreaming(false);
        if (created.status === "ok" || controller.signal.aborted) return;
        setMessages(previous => [...previous, { kind: "error", text: `Сессия не создана: ${created.message}` }]);
        return;
      }
      sid = created.value.session_id;
      setSessionId(sid);
    }
    const result = await streamChat(
      client,
      { backend: { provider_id: "scripted", model: "scripted" }, session_id: sid, ...(trimmedRoot === "" ? {} : { root_id: trimmedRoot }), prompt },
      (event: ChatEvent) => {
        if (controller.signal.aborted) return;
        if (event.type === "delta") setStreamText(previous => previous + event.text);
        else if (event.type === "final") {
          setReport(event.verification_report);
          setMessages(previous => [...previous, { kind: "assistant", text: event.content, report: event.verification_report }]);
          setStreamText("");
        } else {
          setMessages(previous => [...previous, { kind: "error", text: event.error }]);
          setStreamText("");
        }
      },
      controller.signal,
    );
    abortRef.current = null;
    setStreaming(false);
    setStreamText("");
    if (result.status === "stopped") setMessages(previous => [...previous, { kind: "error", text: "Поток остановлен. Исход вызова неизвестен — проверьте журнал и бюджет перед повтором." }]);
    else if (result.status === "error") setMessages(previous => [...previous, { kind: "error", text: result.message }]);
  };

  const stop = (): void => { abortRef.current?.abort(); };

  const files = graph?.status === "ok" ? graph.value : null;
  const treeCount = files === null ? "нет индекса" : pluralFiles(files.length);
  const railBadge = sessions?.status === "ok" ? String(sessions.value.sessions.length) : "—";
  const trimmedRoot = rootId.trim();

  return (
    <div className="app">
      <header className="connection">
        <a href="/dashboard">Atomic Flow</a>
        <form onSubmit={event => {
          event.preventDefault();
          if (!abortRef.current && !reviewBusy) connect(tokenDraft.trim());
        }}>
          <label htmlFor="studio-token">Токен сервера</label>
          <input id="studio-token" type="password" autoComplete="off" maxLength={8192} pattern="[!-~]*" value={tokenDraft}
            onChange={event => setTokenDraft(event.target.value)} disabled={streaming || reviewBusy} />
          <button type="submit" disabled={streaming || reviewBusy}>Подключить</button>
        </form>
      </header>
      <div className="body">
        {/* ── Zone 1a: rail. Icons are text glyphs; dead views say so. ── */}
        <nav className="rail" aria-label="Разделы">
          <button className="rail-item active" type="button" title="Диалог"><span className="rglyph">◍</span><span className="rlabel">Диалог</span></button>
          <button className="rail-item" type="button" disabled title="Открывайте журналы в основном дашборде"><span className="rglyph">≣</span><span className="rlabel">Сессии</span><span className="rbadge mono">{railBadge}</span></button>
          <button className="rail-item" type="button" disabled title="Открывайте историю в основном дашборде"><span className="rglyph">↺</span><span className="rlabel">История</span></button>
          <button className="rail-item" type="button" disabled title="Аналитика и диагностика — Ожидает backend-эндпоинта"><span className="rglyph">◫</span><span className="rlabel">Аналитика</span></button>
          <button className="rail-item" type="button" disabled title="Открывайте настройки в основном дашборде"><span className="rglyph">⚙</span><span className="rlabel">Настройки</span></button>
        </nav>

        {/* ── Zone 1b: Context Explorer from af-client graph read ── */}
        <section className="panel explorer" aria-label="Context Explorer">
          <div className="panel-head">
            <span className="pic">❖</span>
            <span className="title">Context Explorer</span>
            <span className="count mono">{treeCount}</span>
          </div>
          <div className="root-row">
            <input className="root-input mono" value={rootId} disabled={streaming || reviewBusy} onChange={event => {
              if (abortRef.current) return;
              graphRequest.current++;
              setRootId(event.target.value);
              setGraph(null);
              setSessionId(null);
              setMessages([]);
              setReport(null);
            }} placeholder="root_id" aria-label="Идентификатор root" />
            <button className="mini-btn" type="button" onClick={() => { void loadGraph(); }} disabled={trimmedRoot === ""}>Прочитать граф</button>
          </div>
          <div className="tree">
            {files === null ? (
              <div className="panel-empty">
                Граф ещё не собран.<br />Подключите проект и соберите граф в основном дашборде.
                {graph?.status === "error" && <div className="err-text">{graph.message}</div>}
              </div>
            ) : files.length === 0 ? (
              <div className="panel-empty">Граф прочитан, но не содержит файлов.</div>
            ) : (
              files.map((file, index) => (
                <details className="trow-group" key={`${file.path}:${index}`}>
                  <summary className="trow">
                    <span className="name mono">{file.path}</span>
                    <span className={`layer-chip ${file.layer}`}>{file.layer}</span>
                  </summary>
                  {file.symbols.map((symbol, symbolIndex) => (
                    <div className="trow sym mono" key={symbolIndex}>{symbol === "" ? "—" : symbol}</div>
                  ))}
                </details>
              ))
            )}
          </div>
          <div className="query-card">
            <div className="qh">Контекст запроса</div>
            <div className="qtext">Задайте вопрос — контекст появится здесь.</div>
          </div>
        </section>

        {/* ── Zone 2: Workspace dialog + composer ── */}
        <main className="workspace">
          <div className="ws-tabs">
            <span className="agent-tab"><span className="tdot" /> Рабочая сессия</span>
            <span className="workspace-caption mono">{sessionId === null ? "Локальная среда · Ask · сессия не создана" : `Локальная среда · Ask · ${sessionId.slice(0, 12)}`}</span>
          </div>
          <div className="dialog" role="log" aria-label="Диалог">
            {messages.length === 0 && !streaming ? (
              <div className="empty">
                <div className="eic">◉</div>
                <div className="welcome-kicker">CONTEXT → EVIDENCE → VERIFICATION</div>
                <div className="et">Сначала контекст.<br />Затем уверенные решения.</div>
                <div className="es">Подключите проект, изучите его структуру и начните диалог. Источники, проверки и изменения всегда показаны отдельно.</div>
              </div>
            ) : (
              <>
                {messages.map((message, index) => message.kind === "user" ? (
                  <div className="msg user" key={index}>
                    <div className="m-avatar mono">ВЫ</div>
                    <div className="m-body"><div className="m-bubble"><div className="m-text">{message.text}</div></div></div>
                  </div>
                ) : message.kind === "assistant" ? (
                  <div className="msg assistant" key={index}>
                    <div className="m-avatar mono">AF</div>
                    <div className="m-body">
                      {message.report !== undefined && (
                        <div className="m-head">
                          <span className={`verify-badge ${message.report.publication === "published" ? "ok" : ""}`}>{PUBLICATION_LABEL[message.report.publication]}</span>
                        </div>
                      )}
                      <div className="m-text">{message.text}</div>
                    </div>
                  </div>
                ) : (
                  <div className="msg assistant" key={index}>
                    <div className="m-body"><div className="err-text">{message.text}</div></div>
                  </div>
                ))}
                {streaming && (
                  <div className="msg assistant">
                    <div className="m-avatar mono">AF</div>
                    <div className="m-body"><div className="m-text">{streamText === "" ? "…" : streamText}</div></div>
                  </div>
                )}
              </>
            )}
          </div>
          <div className="composer-wrap">
            <div className="composer">
              <div className="mode-row">
                <button className="mode-chip active" type="button" title="Диалог без изменения файлов">Ask</button>
                <button className="mode-chip" type="button" disabled title="Правка кода выполняется через host-approved journey; безопасный контракт публикации не подключён">Edit</button>
                <button className="mode-chip" type="button" disabled title="Планирование и запуск задач появятся после подключения TaskRunner API">Task · скоро</button>
                <span className="mode-note">Диалог без изменения файлов</span>
              </div>
              <div className="input-row">
                <textarea
                  value={composer}
                  rows={1}
                  placeholder="Задайте следующий вопрос..."
                  aria-label="Сообщение"
                  onChange={event => setComposer(event.target.value)}
                  onKeyDown={event => {
                    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) { event.preventDefault(); void send(); }
                    if (event.key === "Escape") stop();
                  }}
                />
                {streaming && <button className="stop-btn" type="button" onClick={stop}>Стоп</button>}
                <button className="send-btn" type="button" onClick={() => { void send(); }} disabled={streaming || reviewBusy || health?.status !== "ok" || composer.trim() === ""} aria-label="Отправить" title="Отправить (Enter)">➤</button>
              </div>
              <div className="composer-foot"><span>Enter — отправить · Shift+Enter — новая строка</span><span>Esc — остановить</span></div>
            </div>
          </div>
        </main>

        {/* ── Zone 3: Verification Summary from evidence types ── */}
        <aside className="panel verify" aria-label="Verification Summary">
          <div className="v-head">
            <span className="vic">⛨</span>
            <span className="title">Проверки и доказательства</span>
            <span className={`v-badge ${report !== null && report.publication === "published" ? "ok" : ""}`}>{report === null ? "не оценено" : PUBLICATION_LABEL[report.publication]}</span>
          </div>
          <div className="v-banner">
            {report === null
              ? "Подтверждённые факты появятся здесь вместе с источником и областью проверки."
              : "Отчёт получен по выбранной области источников. Это данные о проверке, а не разрешение на публикацию или исполнение."}
          </div>
          <div className="v-section">
            <div className="vs-title"><span>Проверки ответа</span><span className="pill">{report === null ? "—" : `${report.claims.length} утверждений`}</span></div>
            {CHECKS.map(([key, title]) => {
              const check = report === null ? null : report[key];
              return (
                <div className={`v-item ${check !== null && check.status === "passed" ? "ok" : check !== null && check.status === "failed" ? "err" : ""}`} key={key}>
                  <span className="vic">{check !== null && check.status === "passed" ? "✓" : check !== null && check.status === "failed" ? "✕" : "•"}</span>
                  <span>{title}: {check === null ? "нет данных" : `${STATUS_LABEL[check.status]} · ${check.passed}/${check.checked}`}</span>
                </div>
              );
            })}
          </div>
          <ReviewedEdit client={client} token={token} connected={health?.status === "ok"} blocked={streaming} setBusy={setReviewBusy} />
          <div className="changes-head">
            <span className="ct">Изменения в проекте</span>
            <span className="draft-chip">нет правок</span>
          </div>
          <div className="v-note">Правки выполняются через host-approved journey; безопасный контракт публикации пока не подключён, поэтому запуск правок остаётся выключенным.</div>
          <div className="v-actions">
            <button className="v-btn" type="button" disabled title="Снимок журнала: POST /v1/sessions/{id}/snapshot ещё не подключён в af-studio">Снимок журнала</button>
            <span className="pending-note">Снимки журнала доступны в основном дашборде.</span>
          </div>
        </aside>
      </div>

      {/* ── Status bar ── */}
      <footer className="statusbar">
        <span className="seg">
          <span className={`dot ${health === null ? "" : health.status === "ok" ? "ok" : "err"}`} />
          <span>{health === null ? "Подключение…" : health.status === "ok" ? `Подключено · v${health.value.version}` : health.status === "error" ? health.message : "Нет подключения"}</span>
        </span>
        <span className="seg">root: {trimmedRoot === "" ? "—" : trimmedRoot}</span>
        <span className="seg">Сессия: {sessionId ?? "—"}</span>
        <span className="seg">Бюджет: {budgetLine(budget)}</span>
        <span className="sp" />
        <span className="seg mono">af-studio 0.1.0 · данные, не разрешения</span>
      </footer>
    </div>
  );
}
