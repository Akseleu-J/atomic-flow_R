# AUDIT RESPONSE — Atomic Flow, 20.11.2026

Ответ на `docs/AUDIT_PACKAGE_2026-11-20.md`. Структура повторяет пакет:
резюме → находки аудита (с `файл:строка`) → ответы на открытые вопросы §6
(ответ → обоснование → источники) → фундаментальные улучшения → пересобранный
план. Секретов в документе нет; значения ключей не приводятся.

Что проверено руками: `af-program/src/beta_access.rs`, `af-cli/src/beta_gate.rs`,
`af-cli/src/server.rs`, `af-cli/src/http_safety.rs`, `af-cli/src/main.rs`,
`af-sandbox/src/registry.rs`, `af-journal/src/lib.rs` (append/checkpoint),
`ADR-0003`, `tools/issuance_server.py`, `.github/workflows/release.yml`,
`rust.yml`, `Cargo.toml`; прогон `target/debug/af.exe doctor`; YAML-проверка
`release.yml` на дубли ключей. **Не проверено:** CI на `4371834` (нет `gh` в
окружении аудита), Studio/TS-код, af-exec/af-sandbox изоляция в глубину.

---

## 0. Вердикт

**NO-GO для рассылки в текущем виде.** Механики реализованы аккуратно
(bounded reads, `deny_unknown_fields`, domain separation подписи, fail-closed
эффекты, хорошая защита локального HTTP от DNS-rebinding), но **гейт пропуска
обходится без какой-либо криптографии** двумя способами (К-1, К-2), а
**релизный workflow невалиден** с коммита N09 (К-3) — официальный артефакт с
пиннутым ключом сейчас просто не собирается. Все три правки маленькие
(≈полдня + один CI-прогон). После них — GO для волны 1.

| # | Серьёзность | Суть | Где |
|---|---|---|---|
| К-1 | Критично | Удаление/переименование `beta-pass.json` = полностью неогейченный продукт | `af-cli/src/beta_gate.rs:266-284`, `:32-44` |
| К-2 | Критично | `AF_BETA_ISSUER_PUBKEY` из env перекрывает пиннутый ключ → участник подписывает себе пропуск сам | `beta_gate.rs:32-33`, `:200-202` |
| К-3 | Критично | `release.yml` содержит дубли `shell`/`run` (стр. 42-50) → GitHub отвергает workflow; плюс `beta/` не существует на tag-push | `.github/workflows/release.yml:41-50`, `:90-94` |
| В-1′ | Высокая | Гейт стоит только в `task_run`; chat/stream, edit-journeys, reviewed-edit, graph build — без гейта | `main.rs:912` — единственный вызов |
| В-2′ | Высокая | `grant_id`/`release_id` для сверки берутся из **неподписанной** обёртки пропуска — сверка тавтологична, релиз к бинарю не привязан | `beta_gate.rs:203-214` |
| В-3′ | Высокая | Офлайн-истечение не запускает self-destruct (он только в online-ветке); нет «last-seen» маркера против отката часов | `beta_gate.rs:266-284` |
| С-1 | Средняя | `--generate-key` печатает приватный seed в stdout (история терминала, логи агентов, транскрипты) | `tools/issuance_server.py:54-58` |
| С-2 | Средняя | Loopback без токена: любой локальный процесс/другой пользователь ОС вызывает `/v1/task-run` с `check_argv` (= запуск команд) | `server.rs:59-60`, `:1312-1318` |
| С-3 | Средняя | N09 «toolchain pin» фактически не действует: `rust-toolchain.toml` удалён (`e5acffe`), CI на `@stable`; smoke-тест идёт по бинарю, который затем пересобирается `cargo auditable` без `--locked` | `release.yml:30`, `:56-60`, `:90-94` |
| С-4 | Средняя | Журнал — один бегущий SHA-256 по всему файлу, не per-event цепочка/Merkle → корень «same-size окна» и невозможности частичной проверки | `af-journal/src/lib.rs:676`, `:695-723` |
| С-5 | Средняя | Живой `af doctor` на диске — бинарь от 19.11 18:42, коммит P09-3 `4371834` от 20.11 18:28 → `journal_health` в выводе отсутствует; хвост В-7 не закрыт | `target/debug/af.exe` |
| Н-1 | Низкая | `hex_32` режет строку по байтам → panic на не-ASCII значении env | `beta_gate.rs:58-66` |
| Н-2 | Низкая | Admin-token в issuer сравнивается не за константное время | `issuance_server.py:160` |
| Н-3 | Низкая | Док-дрейф: §5.1 пакета ссылается на «§6.В-5» для B2B-claims, а В-5 — лицензия; §4.4 утверждает toolchain-pin; ADR-0003 обещает «parent sync», который на Windows невозможен | `AUDIT_PACKAGE §5.1, §4.4`, `ADR-0003` |
| Н-4 | Низкая | `mailto:beta-feedback@atomic-flow.dev` — подтвердить, что домен и ящик реально принадлежат владельцу (иначе фидбек уходит третьему лицу) | `beta_gate.rs:361` |

**Что сделано хорошо (оставить как есть):** `http_safety::guard` — точная
проверка Host + Origin + `Sec-Fetch-Site` + DENY-фрейминг (закрывает
DNS-rebinding и CSRF из браузера, что многие локальные агент-серверы не
делают); constant-time сравнение bearer; bind-policy «не-loopback ⇒ токен»;
`catch_unwind` вокруг `task_run`; честное «ungated» для dev-сборок; ADR-0003
явно формулирует модель угроз.

---

## 1. Находки подробно (с фиксом)

### К-1. Пропуск необязателен
`gate_new_operation`: если файла нет → `GateConfig::from_env()`; он требует
**три** env-переменные (`AF_BETA_GRANT/RELEASE/SERVICE`) через `.ok()?`, у
участника их нет → `None` → `Ok(())`. Итог: `del %USERPROFILE%\.atomic_flow\beta-pass.json`
(или `ATOMIC_FLOW_HOME=<пустая папка>`, `registry.rs:21-26`) снимает гейт целиком.

**Фикс (≈20 строк):** если ключ пиннут при сборке (`BETA_ISSUER_PUBKEY_HEX`
не пуст) — отсутствие пропуска = **отказ**, а не pass-through. Pass-through
только при пустом пиннутом ключе (dev). Тест: «pinned + no file ⇒ Err».

### К-2. Подмена ключа через env
`verify_pass_file` и `from_env` сначала читают `AF_BETA_ISSUER_PUBKEY`.
Участник генерирует свою ed25519-пару тем же `issuance_server.py`, ставит
env — пропуск «валиден». **Фикс:** env-override только под
`#[cfg(debug_assertions)]` или cargo-feature `dev-gate`, которая в
`release.yml` не включается; в релизе ключ = только `option_env!`.

### К-3. Релизный workflow сломан
Шаг «Set reproducible build environment» содержит два `shell:` и два `run:`
в одном mapping (проверено YAML-лоадером с детектом дублей: `DUP ['shell','run'] line 42`).
GitHub отвергает такие файлы с «'run' is already defined» [1][2]; в
снисходительных парсерах побеждает последний `run` и SOURCE_DATE_EPOCH/remap
**молча теряются**. Workflow срабатывает только на тегах/dispatch, поэтому
30 push-проверок этого не видят. Дополнительно: `cargo tree > beta/…` на
tag-push падает (`beta/` создаётся только при dispatch).
**Фикс:** разнести шаги; `mkdir -p beta` безусловно; `cargo auditable build
--locked` **вместо** обычной сборки (один бинарь → smoke → упаковка);
добавить `actionlint` в `checks.yml` [2].

### В-1′. Гейт покрывает не все операции
§3 пакета: «гейт каждой новой продуктовой операции». Фактически единственный
вызов — `main.rs:912` (`task_run`). Studio-чат (`/v1/chat/stream`) — главная
CC-поверхность — работает после истечения окна. **Фикс:** axum-middleware,
вызывающий гейт для всех `/v1/*` кроме `health/doctor/capabilities/budget GET`
+ вызов в CLI-ветках `chat/edit`. Кэшировать решение на ~60 с, чтобы не
верифицировать подпись на каждый SSE-чанк.

### В-2′. Сверка grant/release тавтологична
`expected_grant`/`expected_release` берутся из той же неподписанной обёртки,
что и пропуск, — сравнение всегда проходит. **Фикс:** `release_id` пиннить в
бинарь (`option_env!("AF_BETA_RELEASE")` в release.yml); `grant_id` брать из
подписанного тела (сверять не с чем — и не нужно). Тогда пропуск `beta-rc1`
не открывает `beta-rc2`.

### В-3′. Офлайн-истечение без self-destruct и откат часов
После pivot офлайн-путь — основной, но self-destruct и mailto вызываются только
в online-ветке. **Фикс:** при `Inactive` в офлайн-ветке — тот же
`self_destruct`. Против отката часов — монотонный «last-seen» (max времени из
последних событий журнала + маркер-файл); `now < last_seen − 5 мин` ⇒ отказ.
Это стандартная практика офлайн-лицензирования; Keygen прямо пишет, что
anti-clock-tampering офлайн — забота приложения [3][4].

**Важная честность:** self-destruct — UX-механика, не защита (копия exe
переживает rename). Формулировку в README/письме держать как «по истечении
программа удаляет себя и сохраняет вашу работу», без обещаний невозможности.

### С-1. Приватный seed в stdout
`generate_key` печатает 32-байтовый seed («for the official build») — но в
официальную сборку идёт **публичный** ключ. Печать seed не нужна вовсе.
Если ключ генерировался в сессии агента — seed мог попасть в транскрипт/память
агента (ZCode/Codex). **Рекомендация:** проверить историю/логи той сессии; при
сомнении — ротация ключа *до* рассылки (дешевле сейчас, чем после 300 пропусков).
Печатать `pub hex`; на `key.pem` выставить ACL «только владелец» (`icacls`).

### С-2. Loopback ≠ доверенный вызывающий
Защита от браузера отличная, но любой локальный процесс (вредонос, другой
пользователь Windows, контейнер с host-net) вызывает `task-run`/`reviewed-edit`.
Jupyter решил это per-launch токеном по умолчанию. **Рекомендация:** случайный
токен на каждый `af serve` даже на loopback; Studio получает его через
URL-fragment при открытии (`/studio/#t=…`) и кладёт в sessionStorage.

### С-4. Структура хеш-цепочки
`prefix_sha256` — состояние одного SHA-256 над всем файлом. Отсюда: (а)
same-size правку можно найти только полным рехэшем, (б) нельзя доказать
третьей стороне включение события без всего файла. См. фундаментальное
улучшение Ф-2 (Merkle-лог по C2SP).

---

## 2. Ответы на открытые вопросы §6

### Блок А — дистрибуция

**А-1. Активация пропуска.**
*Ответ:* не (a), а **(d) с жёстким подписанным потолком**: подписывать
`not_before`, `activate_by` (напр. выдача + 7 сут), `max_runtime = 96h` и
`hard_expires_at = activate_by + 96h`. Гейт: первый запуск пишет
`activated_at_local` в журнал/маркер; окно = `min(activated_local + 96h, hard_expires_at)`.
*Обоснование:* опасение пакета «без онлайна это ослабляет» верно лишь
частично — переустановка может сбросить локальный маркер, но **не дальше
подписанного `hard_expires_at`**. Максимальная экспозиция ограничена
криптографически (7+4 сут), а ручная поштучная генерация (a) не нужна —
пачка пропусков генерируется из CSV intake одной командой. Схема
`nbf`/grace-period — стандарт офлайн-лицензий (Keygen license files,
ed25519 offline tokens) [3][4].
*Стоимость:* +3 поля в `AccessDecision` (schema_version → 2), ~0.5 дня.

**А-2. Отзыв.**
*Ответ:* подписанный CRL — да, но **«без сервера» ≠ «без сети»**: класть
`crl.json` (подписанный issuer-ключом, с `sequence` и `issued_at`) на
статический хостинг (GitHub Pages / raw release asset). Гейт пытается скачать
с таймаутом 3 с, принимает только `sequence` ≥ закэшированного; нет сети →
работает по кэшу (fail-open). CRL «в следующей рассылке» почти бесполезен —
офлайн-бинарь его никогда не увидит.
*Обоснование:* модель «статический подписанный артефакт + монотонный номер»
— та же, что у checkpoint'ов transparency-логов (C2SP signed-note) [5];
сервер не нужен, Aeza не нужна.

**А-3. Шеринг.**
*Ответ:* согласен — принять для беты, + **атрибуция**: `grant_id`
вшивается в каждый evidence-export и self-destruct-отчёт, так что «утёкший»
пропуск виден в фидбеке. Device binding — волна 2, через per-install ключ
(участник присылает pubkey при activation, а не HWID: меньше PII, не ломается
при смене железа).

**А-4. AV/SmartScreen.**
*Ответ:* **Azure Artifact Signing** (бывш. Trusted Signing) ≈ $9.99/мес за
5000 подписей — в 20-40 раз дешевле OV-сертификата и даёт базовую репутацию
SmartScreen [6]. Проверить eligibility для физлица/региона владельца до
оплаты. Для волны 1: GitHub release + zip + `SHA256SUMS` **подписанный
отдельным release-ключом** (minisign/ed25519 — инструментарий уже есть;
issuer-ключ для этого не использовать — разделение ролей).
*Поправка к пакету:* GitHub Artifact Attestations для **приватных** репо
требуют Enterprise Cloud [7] — для этого репо недоступны, поэтому именно
minisign.

**А-5. Фидбек.**
*Ответ:* согласен (форма с файлом), плюс `af feedback bundle`: собирает zip
из `beta-final-report/` и открывает Explorer с выделенным файлом
(`explorer /select,`) — работает без почтового клиента. mailto оставить.
Проверить владение доменом (Н-4).

### Блок Б — доверие и ядро

**Б-1. Same-size окно.**
*Ответ:* verify при закрытии — да как дешёвый шаг, но он не случится при
kill/краше; поэтому также verify при **следующем open** (уже есть) и при
`evidence export` (уже есть). Корень — Ф-2: с per-event Merkle-деревом
полная проверка становится инкрементальной и доказуемой.

**Б-2. Retention.** Согласен отложить. Когда дойдёт — проектировать как
tiles-лог (C2SP tlog-tiles): старые тайлы архивируются, подписанный
checkpoint остаётся якорем, удаление не ломает проверяемость [5].

**Б-3. Runtime-часы.** Не делать. Вариант А-1 выше требует только маркер
первого запуска, не runtime-счётчик.

**Б-4. Live-валидация N05.** Включить, но как **воспроизводимый eval**:
фиксированный task-pack, cap бюджета, k≥3 прогонов, формат совместимый с
Harbor (harness Terminal-Bench 2.0) — тогда результаты сравнимы с
Claude Code/Codex/OpenHands на тех же задачах [8]. Разброс от harness'а
на одной модели — до ~18 п.п. [8][9]; это и есть то, что вы измеряете.

### Блок В — инфраструктура

**В-1. Aeza.** *Закрыть.* После А-2 (CRL статикой) сервер для беты не нужен.
Для P10 позже: gVisor на платформе **systrap не требует KVM** и в nested-VM
часто быстрее KVM-платформы [10] — Firecracker не обязателен; любой дешёвый
VPS подойдёт, держать неиспользуемый не нужно.

**В-2. N07 benchmarks.** *Поправка к пакету:* GitHub Free даёт **2000
мин/мес на приватные репо** на стандартных раннерах (Windows ×2) — не
«платные минуты» до исчерпания [11]; RAM раннера (7-16 GB) линкеру хватает.
Но wall-clock бенчи на shared-раннерах шумные → для регрессий использовать
счётчики инструкций (iai-callgrind/Cachegrind, детерминированно в CI), а
wall-clock — на Kaggle как и предложено. Локальный OOM лечится профилем:
`[profile.dev] debug = "line-tables-only"` и `[profile.bench] debug = false`
(заметно меньше символов → меньше память линкера) [12]; `-j1` уже есть.

**В-3. Firecracker/B4a.** Согласен отложить; кандидат на замену — gVisor
(см. В-1) или OS-уровень по модели Codex (Ф-3).

**В-4. T0 residual.** *Сделать сейчас, до рассылки*, и расширить: vault
лежит в OneDrive → есть облачная копия и история версий; ротация
GitHub-токена + issuer-ключа (если С-1 подтвердится).

**В-5. Лицензия.** *Рекомендация:* **FSL-1.1-Apache-2.0** для ядра (запрет
только конкурирующего использования, авто-конверсия в Apache через 2 года —
проще BSL с её переменными) [13]; TS-клиент/протоколы оставить MIT для
экосистемы. Учесть: всё, что уже публиковалось под MIT, остаётся MIT —
смена действует только вперёд.

**В-6. CI на 4371834.** Аудитом не проверено (нет `gh`). Добавить: ручной
`workflow_dispatch` для `release.yml` **после** фикса К-3 — это единственный
способ увидеть, что релиз собирается.

**В-7. Live `af doctor`.** Прогнан: env-проверки PASS (home, sessions, git,
graphs), docker/firecracker FAIL (ожидаемо на этой машине), exit 0. **Но**
бинарь старше P09-3 → `journal_health` в выводе нет. Нужна пересборка af-cli
и повторный прогон; хвост остаётся открытым.

**В-8. Кодекс-хвост.** Решение владельца. Перед удалением дерева
`atomic-flow 2\` — grep на `.env`/токены/ключи, чтобы не оставить копий
секретов в OneDrive-корзине.

**В-9. OS acceptance matrix.** Согласен, чистый док — делать.

### Блок Г — продукт

**Г-1. Parity с Claude Code — приоритеты.** Рекомендованный порядок по
отношению «ценность/стоимость»:
1. **Permission modes + hooks** (pre/post tool) — по публичным разборам
   архитектуры CC каждый инструмент — отдельный permission-gated tool [14];
   у вас уже есть envelope-авторизация (ADR-0001) — это почти бесплатно.
2. **MCP-клиент** (в `af-program` уже есть `mcp.rs`/`mcp_stdio.rs`).
3. **Plan mode** (read-only режим перед правкой).
4. **Сжатие контекста** по принципу ACE «grow-and-refine» вместо полной
   перезаписи summary — полная перезапись даёт «context collapse» [15].
5. **ACP-сервер** (Ф-5) — вместо догонки UI.
6. Subagents, git-интеграция, file-tree — после.
*Оговорка по «сливам»:* исходники Claude Code утекли через npm source map
(v2.1.88, 31.03.2026), Anthropic подтвердил и рассылал DMCA [14]. Использовать
только **публичные разборы архитектуры**, не код: под MIT/FSL-проектом
заимствование утёкшего кода — юридический риск.

**Г-2.** Нужен референс-скрин владельца — без него не оцениваю.

**Г-3. Гибрид-память.** После беты; базой взять ACE (playbook с
инкрементальными структурированными дельтами, ICLR 2026, код открыт) [15].

---

## 3. Фундаментальные улучшения (суть сохраняется)

**Ф-1. Переформулировать модель доверия беты: «атрибуция, а не крепость».**
Офлайн-гейт принципиально обходим (патч бинаря). Цель — сделать честное
использование удобным, а нечестное — *видимым*: подписанный пропуск с
потолком (А-1), CRL статикой (А-2), `grant_id` в каждом артефакте (А-3).
Это снимает давление «усиливать DRM» и экономит недели.

**Ф-2. Журнал → Merkle-лог по C2SP (`tlog-checkpoint`, `signed-note`).**
Per-event листья в дереве; checkpoint (размер + корень) подписывается
per-install ключом; при `evidence export` владелец/третья сторона может
**cosign** checkpoint как witness [5]. Даёт: инкрементальную проверку,
inclusion/consistency-доказательства для отдельных событий и — главное —
превращает «тампер-эвиденцию без якоря» (§5.1) в проверяемую третьей
стороной аттестацию для B2B. Формат открытый, есть реализации на Rust
(siglog) [5]. Это закрывает Б-1, Б-2 и B2B-claim одним дизайном.

**Ф-3. Sandbox по модели Codex: одна API, OS-профили.**
Codex (Rust, Apache-2.0) даёт единый интерфейс «команда + permission
profile» с бэкендами Landlock+seccomp (Linux), Seatbelt (macOS) и
собственным sandbox на restricted tokens (Windows) [16][17]. Для
af-sandbox это прямая замена «Docker или local-trusted»: изоляция без
Docker Desktop на машине участника — именно то, чего не хватает в
`af doctor` выше (docker FAIL → local-trusted). Можно изучить и (с
соблюдением Apache-2.0) переиспользовать.

**Ф-4. Evidence-журнал как топливо для оптимизации harness'а.**
Meta-Harness (Lee, Khattab, Finn et al., 2026) показал: агент-оптимизатор,
читающий файловую систему с кодом прошлых harness'ов, трейсами и скорами,
находит harness'ы лучше ручных на Terminal-Bench 2 [9]. У Atomic Flow уже
есть ровно этот субстрат — детерминированный журнал + evidence + budget
ledger. Стратегически это сильнее, чем UI-parity: «ядро, которое
самоулучшается по собственным доказательствам».

**Ф-5. ACP вместо догонки Studio.**
Agent Client Protocol (Zed + JetBrains, Apache-2.0, есть Rust-крейт, реестр
агентов с января 2026) [18]: реализовав ACP-сервер в af-cli, вы получаете UI
в Zed/JetBrains/Neovim без собственной работы, а Studio остаётся
специализированной поверхностью (evidence, budget, rewind).

**Ф-6. Гигиена сборки как код.** `rust-toolchain.toml` вернуть и
использовать установщик, который его уважает (вместо `dtolnay@stable`,
вызвавшего конфликт в `e5acffe`) — так локальный clippy 1.99 и CI 1.100+
перестанут расходиться (риск из §7); `actionlint`; `cargo-deny`;
minisign-подпись SHA256SUMS.

---

## 4. Пересобранный план (до GO)

1. **[Код, ½ дня] К-1, К-2, В-2′, В-3′** — гейт: pinned ⇒ пропуск
   обязателен; env-override только в dev; release pinned; self-destruct и
   last-seen в офлайн-ветке. Тесты на каждый обход.
2. **[Код, 2 ч] В-1′** — middleware гейта на все `/v1/*` продукта.
3. **[CI, 2 ч] К-3 + С-3** — починить `release.yml`, единый auditable-бинарь,
   `actionlint`; `workflow_dispatch` до зелёного.
4. **[Владелец, сейчас] С-1 + В-4** — проверить утечку seed; ротация токена
   (и ключа при сомнении).
5. **[Код, 1 день] А-1 (schema v2) + А-2 (CRL статикой)**.
6. **[Сборка] С-5/В-7** — пересобрать af-cli, приложить `af doctor --json`.
7. **[Процесс] А-4/А-5** — minisign SHA256SUMS, форма с файлом,
   `af feedback bundle`; проверить домен фидбека. Критерий GO — как в
   пакете: полный цикл на 2 тестерах **+ попытка обхода К-1/К-2 проваливается**.
8. После беты: Ф-2 (Merkle-журнал), Ф-3 (OS-sandbox), Ф-5 (ACP), Ф-4.

---

## 5. Источники

1. Отчёты GitHub Actions «'run' is already defined» (Invalid workflow file): https://www.github.com/ethui/ethui/actions/runs/9066764650 ; https://www.github.com/Misunderstood-Wookiee/LaunchPass/actions/runs/5082793266
2. actionlint — проверка дублей ключей: https://www.github.com/rhysd/actionlint/blob/main/docs/checks.md
3. Keygen — license files, офлайн, clock tampering: https://keygen.sh/docs/api/security/ ; https://github.com/wahello/keygen-go
4. Ed25519 offline tokens, grace periods, clock rollback: https://infosecwriteups.com/asymmetric-signing-machine-fingerprinting-and-offline-grace-periods-building-a-license-system-d8dd5678e1cb
5. C2SP signed-note / tlog-cosignature; siglog (Rust, Tessera-совместимый): https://www.github.com/C2SP/C2SP/blob/main/signed-note.md ; https://www.github.com/C2SP/C2SP/blob/main/tlog-cosignature.md ; https://docs.rs/crate/siglog/0.1.0/source/src/witness/mod.rs
6. Azure Artifact Signing — цены и SmartScreen: https://azure.microsoft.com/pricing/details/artifact-signing/ ; https://azure.microsoft.com/products/artifact-signing
7. GitHub Artifact Attestations (приватные репо → Enterprise Cloud): https://docs.github.com/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds ; https://github.com/actions/attest-build-provenance
8. Terminal-Bench 2.0 / Harbor, зависимость от harness: https://www.snorkel.ai/blog/terminal-bench-2-0/ ; https://arxiv.org/abs/2601.11868 ; https://proceedings.iclr.cc/paper_files/paper/2026/hash/444a3737adaee10d86ad2ef5f74468e6-Abstract-Conference.html
9. Meta-Harness (arXiv:2603.28052): https://arxiv.org/abs/2603.28052 ; HARBOR: https://arxiv.org/pdf/2604.20938
10. gVisor platforms (systrap без KVM): https://gvisor.dev/docs/architecture_guide/platforms ; https://gvisor.dev/blog/2023/04/28/systrap-release/
11. GitHub Actions billing (2000 мин/мес Free, приватные): https://docs.github.com/en/billing/managing-billing-for-github-actions/about-billing-for-github-actions
12. `debug = "line-tables-only"` и размер символов: https://users.rust-lang.org/t/split-debuginfo-packed-produce-much-bigger-binary-than-expected/131473
13. FSL vs BSL, Fair Source: https://blog.sentry.io/introducing-the-functional-source-license-freedom-without-free-riding ; https://lucumr.pocoo.org/2024/9/23/fsl-agpl-open-source-businesses/
14. Утечка исходников Claude Code (npm source map) и разборы: https://venturebeat.com/technology/claude-codes-source-code-appears-to-have-leaked-heres-what-we-know ; https://infoq.com/news/2026/04/claude-code-source-leak ; https://thenewstack.io/claude-code-source-leak/
15. ACE — Agentic Context Engineering (ICLR 2026): https://arxiv.org/abs/2510.04618
16. Codex sandbox (OpenAI): https://openai.com/index/inside-the-codex-sandbox/ ; https://openai.com/index/building-codex-windows-sandbox/
17. Разбор sandbox Codex (Landlock+seccomp): https://simonwillison.net/2025/Nov/9/codex-sandbox-investigation/
18. Agent Client Protocol: https://zed.dev/acp ; https://zed.dev/blog/acp-registry ; https://zed.dev/blog/jetbrains-on-acp

*Оговорки: часть сведений о Terminal-Bench, ACP-адопции и утечке CC — из
вторичных источников; цены Artifact Signing и eligibility физлиц проверить
на официальной странице перед оплатой.*
