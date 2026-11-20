# AUDIT PACKAGE — Atomic Flow, 20.11.2026

Документ для полного аудита владельцем. Здесь: карта всех рабочих путей,
обоснование каждой линии работ (с коммитами), честные границы модели доверия,
открытые вопросы с вариантами решений и операционный рунбук. **Секретов в
документе нет** (правило §9 протоколов): указаны только пути и ссылки на
хранилища, значения — у владельца.

Канонические доки, на которые опирается этот пакет:
`docs/ATOMIC_FLOW_PROTOCOLS_MASTER.md` (протоколы), `docs/ENGINEER_BETA_PLAN_2026-11-10.md`
(B0–B6), `docs/ASSISTANT_HANDOFF.md` (главы P06→P14/E00–E08),
`docs/PRODUCTION_ROADMAP.md` (checklist глав), ADR-0001/0002/0003.

---

## 1. Резюме состояния

- Репозиторий: `https://github.com/Akseleu-J/atomic-flow_R`, ветки `main` и
  `experimental` всегда синхронны (пуш в обе). **r/main = 4371834**
  (P09-диагностика, 19.11). Последний подтверждённо-зелёный CI: `f56721c`
  (🟢 по 24 уникальным проверкам); на `4371834` CI запущен, но итог ещё не
  сверялся (открытый хвост, §6.В).
- Все бета-механики без сервера закрыты и проверены на живом бинаре:
  офлайн-пропуск (e2e), самоуничтожение с сохранением работы пользователя,
  фидбек через mailto, Studio CC-уровня (multi-turn, slash, rewind, BYOK,
  Edit/Task из UI), N09 воспроизводимые артефакты, N05 enrichment целиком.
- 19.11 закрыты два квадратичных долга журнала (P09-1, P09-2) и добавлена
  диагностика (P09-3). Все изменения проведены через полный цикл:
  тесты локально → fmt → clippy → CI → обе ветки.

---

## 2. Карта путей (всё, что важно, с обоснованием)

### 2.1 Рабочее дерево и репо

| Путь | Что это | Обоснование |
|---|---|---|
| `D:\atomic-flow-dev` | **Основная dev-копия** (переехала с C: 11.11 по приказу «не заполняй C:») | Все коммиты, тесты, сборки идут отсюда; remote `r` = GitHub, `dev-c` = legacy |
| `D:\atomic-flow-dev\rust\` | Rust workspace: af-cli, af-loop, af-journal, af-exec, af-evidence, af-program, af-graph, af-llm, af-budget, af-sandbox, af-context, af-agents, af-entropy, af-memory | Ядро; `/rust/target/debug/af.exe` — собранный CLI (сборка см. §8) |
| `D:\atomic-flow-dev\ts\af-studio\`, `ts\af-client\` | Studio (React/vite) и TS-клиент | Поверхности; сборка Studio → `af serve` раздаёт dist |
| `D:\atomic-flow-dev\tools\issuance_server.py` | Issuer: keygen, sign, `--generate-pass`, `--selftest`, `--fixture` | Единственный источник подписанных пропусков; серверная часть (`--serve`) осталась как опция |
| `D:\atomic-flow-dev\docs\` | Протоколы, планы, ADR, BETA-кит | Канон знаний; `AUDIT_PACKAGE` — этот файл |
| `D:\atomic-flow-dev\.local-stash\` | Личный stash (не коммитится) | Черновые артефакты сессий |
| `D:\af-kaggle\` | Kaggle kernels (S3c) | Ядро строится и тестируется в Kaggle; policy §память: последовательные запросы, акк.2 |

### 2.2 Хост-состояние приложения (Windows, владельца)

| Путь | Что это | Обоснование |
|---|---|---|
| `C:\Users\omirb\.atomic_flow\` | User dir ядра: `sessions/`, `graphs/`, `budget/`, `tasks/`, `workspaces/`, `providers.json`, `crashes/`, `studio-dist/` | Рабочие данные и журналы; journal = append-only JSONL + sidecar-чекпойнты |
| `C:\Users\omirb\.atomic_flow\issuance\key.pem` | **ed25519 issuer-ключ владельца** (seed-пара) | Единственный authority пропусков; утечка = подделка пропусков. Значение не хранится нигде кроме этого файла |
| `C:\Users\omirb\.atomic_flow\issuance\key.pub.pem` | Публичный ключ; hex `b7df426b...f5e6921ab` | Пиннится в официальный бинарь через `option_env!("AF_BETA_ISSUER_PUBKEY_HEX")` + release.yml |
| `C:\Users\omirb\.atomic_flow\beta-pass.json` | Тестовый офлайн-пропуск (grant `engineer-beta-1`, release `beta-rc1`) | Использовался для e2e-проверки гейта; срок виден в `af beta` |
| `C:\Users\omirb\.atomic_flow\beta-final-report\` | Куда self-destruct складывает evidence + отчёт | Механика сохранения работы пользователя |

### 2.3 Хранилища секретов и учёток (значения — только у владельца)

| Путь | Что это | Обоснование |
|---|---|---|
| `C:\Users\omirb\OneDrive\Документы\ChatGPT\computer_control\shared-access\.env.enc` | AES-GCM vault: GitHub token (+ прочие учётки) | Правило §9: секреты никогда в коммитимые файлы/чат/логи; пароль vault знает ТОЛЬКО владелец |
| `C:\Users\omirb\OneDrive\Документы\ChatGPT\kaggle_push\` | Скрипты разблокировки Kaggle-аккаунтов | Акк.2/акк.3 policy |

### 2.4 Инструменты сборки (критично для воспроизводимости локальной сборки)

| Путь | Что это | Обоснование |
|---|---|---|
| `C:\Users\omirb\.cache\mingw64\mingw64\bin\` | MinGW binutils (dlltool/as/ld) | Без него `windows-sys` не собирается (dlltool не найден / CreateProcess падает); канон-PATH в `docs/ATOMIC_FLOW_PROTOCOLS_MASTER.md:30-31` |
| `C:\Users\omirb\.cargo\bin\`, `C:\Users\omirb\.rustup\toolchains\stable-x86_64-pc-windows-gnu\...\bin\self-contained\` | cargo/rustc + self-contained dlltool | GNU-тулчейн по умолчанию; MSVC-тулчейн установлен, но VS Build Tools на машине НЕТ |
| `C:\Users\omirb\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\powershell\pwsh.exe`, `...\git\cmd\` | pwsh и git, используемые из скриптов | Пуш-цепочка (§8) |

### 2.5 Внешние ресурсы

| Ресурс | Статус | Обоснование |
|---|---|---|
| GitHub `Akseleu-J/atomic-flow_R` | active, CI на каждом пуше | 30 check-runs: cargo test ×3 OS, fmt, clippy -D warnings, studio, TS, python matrix, Real Docker acceptance ×4 |
| Aeza VPS `89.208.97.253` (1c/2GB) | **истёк 17.11**, systemd af-issuance.service развёрнут | После pivot 17.11 сервер опционален; Firecracker там невозможен (no nested KVM), Docker — возможен (вариант для P10) |
| Память ZCode: `C:\Users\omirb\.zcode\cli\memories\projects\7a9e...-...\memory\` | MEMORY.md + 10 файлов | Мой персистентный контекст между сессиями (статусы, ловушки, решения) |

### 2.6 Хвосты для уборки (аудит-пункты)

| Путь | Обоснование уборки |
|---|---|
| `C:\Users\omirb\OneDrive\Документы\ChatGPT\atomic-flow 2\atomic-flow\` | Дерево кодекс-линии (WIP перенят и приземлён как b4606f5); удалять после подтверждения остановки кодекс-сессии |
| Старое C:-дерево атомфлоу (до переезда) | По приказу «не заполняй C:» — инвентаризировать и удалить/архивировать |
| `D:\atomic-flow-dev\rust\target\` (~неск. GB) | Держать только debug; release-артефакты собираются в CI (N09) |

---

## 3. Архитектура одной страницей

**Ядро (Rust, GNU-тулчейн):** af-cli (CLI + HTTP-сервер Studio + beta-гейт +
doctor + crash capture) → af-loop (TurnLoop + guided edit + enrichment по
ADR-0002) → af-journal (append-only журнал сессий + сегменты-субстрат) →
af-exec (worker auth S0, подписанные конверты ed25519) → af-program
(beta_access верификатор, ring, замороженный вектор openssl↔ring) →
af-sandbox/af-budget/af-evidence/af-graph/af-llm/af-context/af-agents/af-entropy/af-memory.

**Поверхности:** Studio (React, три зоны, BYOK — ключи не покидают хост),
TS-клиент с валидатором evidence v2, Python-хост (wheel, миграция по языковому
плану: Python host + Rust(PyO3) ядро + TS).

**Деньги/бюджет:** нанодолларовый append-only ledger с hold-семантикой;
BYOK — провайдер выбирается в браузере.

**Доверие:** ed25519 issuer → офлайн-пропуск (подпись + окно 96ч) → гейт
каждой новой продуктовой операции (`task_run`, первая строка) → при отказе
онлайна self-destruct с сохранением пользовательской работы + фидбек-mailto.

---

## 4. Сделано и обосновано (по линиям, с ключовыми коммитами)

### 4.1 Бета-механики без сервера (решение владельца 17.11 — pivot)

- **Офлайн-пропуск** (`8302857` гейт, `c95fdd5` генератор): подписанный JSON
  (`decision_b64`+`signature_hex`), домен `atomic-flow/beta-access/v1\0`,
  окно ≤96ч, `verify_offline_pass` без challenge/30s-freshness. Генерация:
  `python tools/issuance_server.py --generate-pass pass.json --key key.pem
  --grant engineer-N --release beta-rc1`. **Обоснование:** pivot убрал
  серверную зависимость; e2e на живом бинаре: валид → admission queue,
  байт-подделка → отказ, `af beta` показывает остаток окна (`114ed08`).
- **Самоуничтожение + сохранение работы** (`0b5cd53`+`3ed8e3c`): evidence
  export + crash log → `beta-final-report/`, rename exe + MoveFileExW
  delete-on-reboot, studio-dist удаляется. **Обоснование:** обязательство
  «96ч и программе конец» без нарушения целостности данных участника.
- **Фидбек-mailto** (`3ed8e3c`): открывает почтовый клиент с темой/телом и
  знаменателями формы из `docs/BETA_FEEDBACK_KIT.md`. **Обоснование:** без
  SMTP-креденшалов (секреты), но см. вопрос §6.В-8.

### 4.2 P09 — надёжность журнала (19.11)

- **P09-1** (`529723c`→`cdd790e`): append O(новые байты) — убран
  квадратичный prefix-rehash; **checkpoint sidecar**
  (`sessions/session_<id>.jsonl.checkpoint`, атомарный tmp+fsync+rename) —
  tripwire при расхождении (→ полная ревалидация) и якорь тампер-эвиденса
  при любом полном чтении; truncate→отказ; foreign-tail discovery;
  детерминированный тест `tail_bytes_scanned==0`. Дизайн: `docs/ADR-0003`.
  **Обоснование:** 96ч-сессии с сотнями ходов делали каждый append O(сессия).
- **P09-2** (`f56721c`): `begin_effect`/`require_effects_clear`/
  `finish_effect` больше не парсят весь журнал на каждый эффект —
  инкрементальный `EffectLedger` (pending/charges/effects/unknown),
  единая реализация (снапшотные методы делегируют), equivalence-тест
  против полного пересчёта; fail-closed исходы сохранены дословно.
- **P09-3 диагностика** (`4371834`): `SessionJournal::diagnostics(verify)` —
  read-only отчёт (state/ledger/checkpoint freshness/integrity pass, ошибки
  полями, никогда не исключениями); `af doctor` → `journal_health` по 8
  свежим сессиям + полный verify новейшей. **Обоснование:** оператор беты
  должен видеть здоровье сессий участника без SSH и ручных разборов.

### 4.3 CC-уровень Studio и Edit/Task из UI

- multi-turn из журнала (хост-владение, последние 8 ходов), markdown-lite,
  tokens/cost мета, slash `/new /clear /resume /help`, session picker
  (`9f55de5`+`47b171b`); `/v1/task-run` + `/v1/edit-journeys`, mode-chip,
  file selector (`14a27c9`+`a63ed56`); rewind/snapshot endpoints +
  кнопка (`af3f83e`+`dd39ebc`). **Обоснование:** требование владельца
  «полный подобно claude code интерфейс»; хост-владение журналом = никаких
  серверных копий переписки.

### 4.4 N05 enrichment и N09 reproducible

- N05 весь (S1a/S1b/S2a/S2b/S3a/S3b + S3c Kaggle kernel v12, 382 passed):
  enrichment-записи в журнале, call_ref, hold-тесты. Live-валидация —
  отдельная кампания (вопрос §6.В-14).
- N09 (`3cdce0c`): toolchain pin, SOURCE_DATE_EPOCH, remap-path-prefix,
  cargo-auditable SBOM. **Обоснование:** воспроизводимый артефакт = основа
  доверия к бинарнику, который участник запускает у себя.

### 4.5 B1 обе стороны, S0 worker-auth, T1-кит

- issuance (серверная опция + локальный генератор), client-wiring, пин
  ключа через `option_env!`+release.yml; worker-auth S0 (mutual ed25519);
  T1: evidence export, doctor human, budget, init wizard, crash capture,
  README-BETA.md, hands-on (найден и починен Illegal-invocation fetch баг
  `de06be7`). **Обоснование:** минимум, при котором бета честна: пропуск,
  бюджет, диагностика, аварийные логи.

---

## 5. Модель доверия и её честные границы

1. **Хеш-цепочка журнала — тампер-ЭВИДЕНЦИЯ, не attestation** (ADR-0003):
   без доверенного якоря цепочка не доказывает честность третьей стороне.
   Sidecar-чекпойнт — якорь «последнего checkpoint'а», но он в той же
   привилегии, что и файл. Same-size правка старых байт ловится только
   полным чтением (окно = жизнь процесса-владельца). Для беты этого
   достаточно; для B2B-claims — см. вопрос §6.В-5.
2. **Офлайн-пропуск не отзываем**: подпись валидна до expires_at, сети нет.
   Скопированный файл = доступ. Revocation/device-binding — решение
   владельца (§6.В-2/3).
3. **Гейт не форт**: dev-сборка без пиннутого ключа честно сообщает
   «ungated»; официальный артефакт пиннит ключ на этапе упаковки.
4. **Sandbox-границы**: Docker-профиль проверяется Real Docker acceptance;
   Firecracker/B4a требует KVM-хоста; локальный trusted-fallback не
   маскируется под изоляцию (никакого silent fallback).
5. **Секреты**: только vault (§2.3); issuer-ключ только на хосте владельца;
   в CI ключ пиннится из секретов GitHub при сборке релиза.

---

## 6. Открытые вопросы (нужен продвинутый ответ владельца)

Формат: суть → варианты → моя рекомендация.

### Блок А — дистрибуция беты (критично до GO)

**А-1. Активация пропуска.** Сейчас `expires_at = момент генерации + 96ч`.
Для 300–500 мест время тикает с выдачи, не с установки участника.
Варианты: (a) генерировать пропуск по запросу (скрипт на каждого — ручной
поток); (b) activation round-trip: участник шлёт challenge → владелец
подписывает activation (почта/форма — пауза вhours); (c) считать 96ч
RUNTIME, а не wall-clock (прошивать счётчик runtime в бюджет/журнал —
усложнение ядра); (d) выдавать пропуск со «свободным стартом»: подписать
`not_before` и увеличить окно до 96ч+буфер, гейт считает окно от первого
запуска (первый запуск фиксируется в локальном маркере, подписанном... без
онлайна это ослабляет). **Рекомендация: (a) для волны 1** (ручная выдача
по мере intake — контроль и обратная связь), для волны 2 — (b).

**А-2. Отзыв/перевыпуск.** Пропуск офлайн не отзываем. Варианты: CRL-файл
в следующей рассылке (гейт проверяет список отозванных grant_id — файл
подписывается issuer'ом); короткие окна (24ч) + перевыпуск; сервер-опция.
**Рекомендация: подписанный CRL-файл в бинаре/рядом** — офлайн-совместимо,
`verify_offline_pass` проверяет список отозванных grant_id.

**А-3. Шеринг пропуска.** Один файл = доступ для любого. Варианты:
device binding (HWID-хеш в decision, проверяется локально; participants
пересылают HWID заранее — трение), ничего (принять для беты), (А-2 CRL
частично закрывает). **Рекомендация: для беты принять + CRL как кнут;
device binding — для волны 2/B2B.**

**А-4. AV/подпись.** Не подписанный exe в email — риск false positive и
пометок SmartScreen. Варианты: подпись кода (сертификат OV ~$200-400/год —
нужно решение по бюджету), zip-архив с checksum + инструкция, ссылка на
GitHub release (репо приватный/публичный?). **Рекомендация: GitHub release
+ zip + sha256 в письме; подпись — перед волной 2.**

**А-5. mailto-фидбек не гарантирован** (нет почтового клиента → потеря).
Варианты: fallback «скопируйте файл beta-final-report на форум», intake
форма принимает вложения. **Рекомендация: форма с загрузкой файла** (в
T2-ките она уже описана) — mailto остаётся бонусом.

### Блок Б — доверие и ядро

**Б-1. Same-size окно (ADR-0003).** Принять как есть / добавить периодический
фоновый verify (по N событиям или при закрытии сессии) / verify при выходе.
**Рекомендация: verify при закрытии сессии** (дёшево, один раз).

**Б-2. Retention/архивация.** `segments.rs::retain` отказывается деструктивных
операций до «anchored archival manifest + crash recovery». Нужен дизайн:
что удаляем, что архивируем, кто проверяет. **Рекомендация: отложить до
после беты** (64MiB cap держит проблему маленькой).

**Б-3. Runtime-часы vs wall-clock** (если А-1(d)) — влияет на af-budget
(hold-семантика) и журнал. **Рекомендация: не делать в бете.**

**Б-4. Live-валидация N05** — отдельная кампания с реальными LLM-ходами
(бюджет: копейки, но нужен ок владельца). **Рекомендация: включить в бету**
как один из task-паков.

### Блок В — инфраструктура и хвосты

**В-1. Aeza (истёк 17.11).** Продлевать (P10 Docker-воркер, TLS для
issuance-опции) или закрыть до решения по бете. **Рекомендация: продлить
на 1 месяц**, если решаем делать P10 на нём; иначе закрыть.

**В-2. N07 benchmarks (OOM линкера на 3.4GB).** Варианты: Kaggle (4 CPU /
29GB RAM — линкер справится; policy: последовательные запросы, акк.2),
GitHub Actions runner (7GB, бесплатно для паблик... репо приватный → платные
минуты), аренда на день. **Рекомендация: Kaggle kernel** с cargo bench —
нулевая стоимость, уже отлажен цикл пуша.

**В-3. B4a Firecracker** — только dedicated/KVM-passthrough хост. Отложить
до сигналов беты (обоснование: изоляция Docker уже закрывает бета-риски).

**В-4. T0 residual**: ротация GitHub-токена владельцем, проверка
shared-access (кто ещё видел vault). **Рекомендация: сделать до рассылки**.

**В-5. Лицензия T2.5** (MIT сейчас) — решение dual/BSL до wave 2.
**Рекомендация: определить до первых B2B-контактов.**

**В-6. CI на `4371834`** — сверить 30 check-runs (последний пуш).
**Рекомендация: поллинг — первая строка плана.**

**В-7. Live-прогон `af doctor`** — сборка завершилась, но живой прогон был
прерван аудитом. **Рекомендация: прогнать и приложить вывод к аудиту.**

**В-8. Кодекс-хвост**: подтвердить остановку кодекс-сессии → удалить
`...\atomic-flow 2\` дерево и старое C:-дерево. 

**В-9. OS acceptance matrix (P09-4)** — документ «где install-only, где
настоящий multiprocess/lifecycle тест» (Windows/Linux/macOS). **Чистый док**
— могу сделать без инфраструктуры.

### Блок Г — продукт

**Г-1. Studio parity с Claude Code:** что осталось из «полного подобия»?
Кандидаты: git-интеграция (auto-commit — roadmap B2B Tier), file-tree,
MCP-клиент, agent-modes. Нужен список приоритетов владельца.

**Г-2. Dashboard UX** (память: нативные диалоги, datalist из ядра, референс-скрин)
— статус после CC-pass? Требуется ревизия референса.

**Г-3. Гибрид-память** (B2B Tier) — после беты.

---

## 7. Риски и митигации (топ-8)

| Риск | Вероятность/эффект | Митигация |
|---|---|---|
| AV блокирует артефакт у участника | средняя/высокая | А-4 (GitHub release + checksum; подпись перед wave 2) |
| Участник теряет фидбек (нет mailto) | средняя/средняя | А-5 (форма с файлом) |
| Пропуск тикает до установки (А-1) | высокая/средняя | волна 1: выдача по запросу |
| Шеринг пропуска | средняя/низкая (бета) | А-3 + CRL (А-2) |
| OOM/fork-сбои локальной машины | высокая/задержки | канон-PATH, -j1, паузы; тяжёлое — в Kaggle/CI |
| CI clippy-дрейф (1.99 vs 1.100+) | средняя/задержки | гонять fmt+clippy локально перед пушем (рунбук §8) |
| Self-destruct без повторного запуска af | низкая/средняя | срок в README + напоминание в письме; вопрос таймера — Б/А план |
| Утечка issuer-ключа | низкая/критическая | ключ только на хосте; при компрометации — новый ключ + перевыпуск (keygen в issuer-туле есть) |

---

## 8. Операционный рунбук (как я работаю — для аудита и повторения)

**Сборка ядра (Git Bash, ВНЕ песочницы):**
```
cd /d/atomic-flow-dev/rust
PATH="/c/Users/omirb/.cache/mingw64/mingw64/bin:/c/Users/omirb/.cargo/bin:\
/c/Users/omirb/.rustup/toolchains/stable-x86_64-pc-windows-gnu/lib/rustlib/\
x86_64-pc-windows-gnu/bin/self-contained:$PATH" \
AF_BETA_ISSUER_PUBKEY_HEX=b7df...21ab cargo build -p af-cli -j1
```
(inline PATH без export; канон: `docs/ATOMIC_FLOW_PROTOCOLS_MASTER.md:30-31`)

**Тесты/гейты перед пушем:** `cargo test -p <crate>` → `cargo fmt -p <crate>`
→ `cargo clippy -p <crate> --all-targets -j1 -- -D warnings`. Ловушки:
локальный clippy 1.99 не ловит `needless_borrows_for_generic_args` (ловит CI
1.100+); строка doc-комментария, начинающаяся с `+`, = markdown list-item
(`doc_lazy_continuation`); STATUS_STACK_BUFFER_OVERRUN = OOM (пауза/повтор);
«found staticlib X instead of rlib» = гниль cargo-состояния →
`cargo clean -p X`.

**Пуш (обе ветки всегда):** inline-pwsh -File скрипт с vault-расшифровкой
(`.env.enc` → GITHUB_TOKEN → extraheader) — `with-github.ps1` не ходит на
HTTPS-ремоуты; bash-экранирование в `pwsh -Command` ломает переменные →
только `-File`.

**Выпуск пропуска участнику:**
```
python tools/issuance_server.py --generate-pass <out.json> \
  --key C:\Users\omirb\.atomic_flow\issuance\key.pem \
  --grant engineer-<N> --release beta-rc1
```
→ письмо: zip-артефакт + pass.json + README-BETA.md + sha256; участник кладёт
pass.json в `~/.atomic_flow/beta-pass.json`; `af beta` — статус.

**Диагностика участника:** `af doctor` (env + journal_health) →
`af evidence export` → файл в `beta-final-report/` → форма/форум.

---

## 9. Конспект плана, который предлагаю выстроить (по приёмке)

1. **[В] Сверка CI на 4371834 + live `af doctor`** — 30 минут, закрывает хвосты В-6/В-7.
2. **[А] Дистрибуция волны 1**: А-1(a) выдача по запросу, А-2 CRL (код:
   `verify_offline_pass` + проверка отозванных grant_id из подписанного
   файла — ~1 день), А-4 GitHub release+checksum, А-5 форма. Критерий: полный
   цикл «письмо → установка → пропуск → работа → фидбек» пройден на 2 testers.
3. **[В] N07 на Kaggle** (kernel с cargo bench) — закрывает P08-измерения
   без железа.
4. **[Док] OS acceptance matrix + failure-soak runbook** (P09-4/6) — 1 день.
5. **[Код] P08 метрики**: phase latency / cancel latency в журнал и evidence
   (bounded) — 2-3 дня.
6. **[Владелец] Решения**: А-2/А-3 модель, В-1 Aeza, В-4 токен-ротация,
   В-5 лицензия, Г-1 приоритеты parity.
7. **После сигналов беты**: P10 (Docker-воркер на продлённом Aeza),
   P11 release foundation, E-блок, B4a, P12-P14.

---

## 10. Что мне нужно для профессиональной работы дальше

1. **Решения по §6** — особенно А-1/А-2/А-3 (модель пропуска) и В-1 (Aeza):
   они определяют, что кодить в следующие 2-3 дня.
2. **Бенчмарк-лан** (Kaggle достаточно) — иначе N07/P08 навсегда «blocked
   by OOM».
3. **Право на CRL-механику** (если одобрите А-2) — это единственное новое
   ядро-изменение, которое я считаю нужным до GO.
4. **Подтверждение остановки кодекс-сессии** — чистка хвостов §2.6.
5. **Референс-скрин для Studio** (Г-2) — чтобы UX-правка не ушла от канона.
6. **Формат фидбек-обработки**: кто и как читает evidence-экспорты
   (я могу сделать `af feedback summarize` — агрегатор по папке экспортов).

---

*Файл живёт в репо (`docs/AUDIT_PACKAGE_2026-11-20.md`) — обновляется после
каждого закрытого вопроса; аудит-хвосты: CI 4371834, live doctor.*
