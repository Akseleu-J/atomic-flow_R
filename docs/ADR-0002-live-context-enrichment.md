# ADR-0002: N05 — live-семантика контекста под бюджет-протоколом

Дата: 09.11.2026. Статус: draft, на согласование владельца.
Основание: `docs/PRODUCTION_STATUS_2026-11-04.md` §N05, `docs/REAL_API_BENCHMARK_PROTOCOL.md`,
`docs/ATOMIC_FLOW_PROTOCOLS_MASTER.md` §9, `docs/NATIVE_PACKAGES_N01-N06_2026-11-05.md` §N05.

## 1. Постановка

N05 «Semantic understanding and complete context» (главы P03/P04/E02): dependency/revision-bound
enrichment/tours/impact, scoped caches, explicit completeness, pinned negative/no-answer evidence.

Что уже есть (важно: транспорт — НЕ недостающая часть):

- Live-транспорт бюджет-гейтован целиком: `rust/af-cli/src/trusted_provider.rs` — `select()` отказывает
  до создания бэкенда при `has_hold()` («reconcile the original attempt before another send»);
  `AccountedBackend` ведёт каждый send по циклу reserve → begin_send → call → settle/mark_unknown;
  unknown лочит hold до reconcile, повторы/реплеи невозможны по правилам переходов ledger.
- Live-провайдер активируется только host-конфигом (`providers.json` / `AF_STUDIO_PROVIDER_CONFIG`),
  с политикой endpoint (запрет plaintext-кредов и удалённого plain HTTP) и потолком резерва.
- `af task run` по умолчанию scripted (`scripted://local`) и обходит ledger — детерминированный путь
  не меняется. Проверка без admitted checker завершается `Unverified` по контракту.

Чего нет — и что составляет N05: модельное обогащение контекста (tour/impact) вокруг основного цикла
правки, кэш таких обогащений, явная полнота и негативные свидетельства.

## 2. Решения (D1–D6)

**D1. Один ledger на задачу.** Enrichment-вызовы резервируются из того же `af_budget::Ledger`, что и
основные sends. Отдельного канала нет; hold от enrichment блокирует отправку так же, как hold от send,
и наоборот. Enrichment резервирует до старта основного цикла, поэтому остаток после него всегда виден
циклу; если cap исчерпан — основной цикл получает явный отказ admission (честное поведение, не
деградация). Специального приоритета не вводим.

**D2. Enrichment опционален и не блокирует.** Точка встраивания — `af_loop::edit::run_edit_task`
до `TurnLoop`: если выбран live-провайдер и ledger допускает reserve — запрос tour/impact по цели
правки, результат попадает в стартовый контекст запроса. Нет провайдера / hold / отказ →
детерминированный путь как сегодня; enrichment помечается Unavailable в отчёте. Деградация тихая
в поведении, явная в evidence.

**D3. Кэш revision-bound.** Ключ записи: (source binding repo+commit, цель: пути/диапазон, kind:
tour|impact, модель, schema-версия промпта). Попадание = 0 модельных вызовов и 0 списаний; в записи —
ссылка на породивший call. Инвалидация по смене revision — как у graph summaries (delta-события).

**D4. Negative evidence — первоклассный исход.** NoAnswer/NotRelevant пишется в журнал и evidence
столь же полно, как успешный tour: вызов был, списание было, ответ — «релевантного нет». Отсутствие
записи никогда не интерпретируется как «ответа не было».

**D5. Completeness явный.** Каждая запись несёт {full|partial|none} и перечень покрытого
(файлы/символы); попадает в `evidence_coverage` `VerificationReport` как данные, не как ручной текст.

**D6. Live-прогоны — только по benchmark-протоколу.** Инженерные слайсы S1–S3 идут на ScriptedBackend
(mock-LLM; шаблоны — journey-тесты `af-loop/src/edit.rs` и тесты `trusted_provider.rs`) — ни одного
реального вызова. Реальная live-валидация N05 — отдельной кампанией по `REAL_API_BENCHMARK_PROTOCOL`
(фиксированный бюджет, аккаунт по Kaggle-policy, чистый SHA, последовательные запросы, unknown → hold,
без ретраев) и только с явного одобрения владельца.

## 3. Слайсы и приёмка

| Слайс | Содержимое | Приёмка |
|---|---|---|
| S1a | Детерминированный каркас: типы EnrichmentRecord/NoAnswer/Completeness, revision-bound JSONL-кэш (`af-loop::enrich`), Unavailable не кэшируется (D2), NoAnswer первоклассный (D4) | Юнит-тесты крейта; af-loop зелёный локально |
| S1b | Запись enrichment в журнал сессии: событие `enrichment` (EVENT_TYPES+1, call_id отсутствует — нейтрально для hold-леджеров); детерминированный путь пишет явный Unavailable (D2/D4). **Поле в VerificationReport перенесено в S3**: контракт frozen (`deny_unknown_fields` + pinned `schema_version`) — добавка поля = cross-language bump фикстур и TS-векторов, это отдельная приёмка | Journey-тест edit.rs + vocabulary-lock тест; af-journal и af-loop зелёные |
| S2 | Live-проводка по D1–D2: enrichment через `AccountedBackend`; семантика hold/refusal/unknown; call_ref заполняется | Тесты на ScriptedBackend-обёртке (шаблон — тесты `trusted_provider.rs`); hold лочит оба пути |
| S3 | Поверхность: флаг в `af task run`, отдача в Studio, поле enrichment в `VerificationReport` (bump wire-контракта: VERSION, фикстуры, TS-вектора) | Mock-LLM journey-тест; полный Kaggle Linux прогон; обновление `PRODUCTION_STATUS` |

Live-валидация — после приёмки S1–S3, отдельной кампанией (D6).

## 4. Вне скоупа

N07–N12 (Linux worker, installed release, corporate profile, live-грады). Контракты §6 handoff не
ослабляются: enrichment наследует unknown→hold, exact-plan default, `--yes` без расширения полномочий,
разделение Local/CI/live статусов.
