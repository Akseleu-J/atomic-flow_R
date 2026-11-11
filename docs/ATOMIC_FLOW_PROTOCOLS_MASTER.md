# ATOMIC FLOW — МАСТЕР-ПРОТОКОЛ РАБОТЫ
Единый документ: пути, протоколы, ловушки, состояние. Дополнять, не дробить.
Аналог в памяти ассистента: `ATOMIC_FLOW_PROTOCOLS.md` + `atomic-flow-project-setup.md` + `hackathon-skillradar.md`.

## 0. Пароль vault
Значение пароля не публикуется в доках — единственное место: менеджер паролей владельца; ассистент запрашивает в сессии и не сохраняет.
История 09.11.2026: значение утекло в публичный `r/main` через прежний §0; история переписана (скраб, `e8b937b`); пароль временно ротировали, но владелец вернул прежний пароль (осознанное решение после скраба). Остаточный риск — GitHub держит старые коммиты по прямым SHA до GC; закрыть: заявка в GitHub Support на purge unreachable-коммитов + проверка шеппинга OneDrive-папки `computer_control/shared-access/` (+ рекомендация: ротация токенов GITHUB/Kaggle при удобном случае).
Vault-файл: `C:\Users\omirb\OneDrive\Документы\ChatGPT\computer_control\shared-access\.env.enc` (AES-GCM + PBKDF2-SHA256; схема расшифровки — в `with-github.ps1`).
Ключи внутри: `GITHUB_TOKEN`, `Kaggle1..5_TOKEN` (токен 3 = акк. umirbayulgaisha, разрешён).

## 1. Копии проекта и репозитории
| Копия | Путь | Роль | Ремоуты |
|---|---|---|---|
| **dev-копия** (активная, Rust-линия; **ПЕРЕЕХАЛА на D: 11.11** — не заполнять C:) | `D:\atomic-flow-dev` | вся Rust-разработка; codex-сессия временно живёт в старом C:-дереве (`...\.zcode\workspace\7a9e7cc1-...\atomic-flow-dev`, его target удалён) — его локальные коммиты подтягивать на D: перед работой (`git fetch dev-c`) | `r` = github.com/Akseleu-J/atomic-flow_R (PUBLIC, main=experimental), `github` = .../atomic-flow.git, `origin` = OneDrive-копия, `dev-c` = старое C:-дерево (только чтение) |
| **af-kaggle** (Kaggle-скрипты полного цикла) | `D:\af-kaggle` | prepare/poll/fetch kernel-цикл | — |
| **OneDrive-копия** (эталон Python-линии) | `C:\Users\omirb\OneDrive\Документы\ChatGPT\atomic-flow 2\atomic-flow` | Python-платформа, codex-сессия работает ЗДЕСЬ | `github` (public python-репо), своя история |
| **Kaggle-копия** | датасеты `umirbayulgaisha/af-native-src-1106` и kernel-артефакты | Linux-прогоны | — |

Git identity для коммитов: Omirbay Akseleu (уже в конфигах копий).

## 2. Git / пуш-протокол
- git НЕ в PATH: `export PATH="/c/Users/omirb/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/git/cmd:$PATH"` (Git Bash) или `...native\git\cmd` (cmd).
- Пуш через vault: `with-github.ps1 -Password (SecureString) -GitArguments @('push','r','experimental:experimental','experimental:main')` — pwsh7 (`...native\powershell\pwsh.exe`); Windows PowerShell 5.1 падает на AesGcm.
- Python-вариант: `printf '<пароль из менеджера паролей>\n' | OneDrive/.venv/Scripts/python.exe OneDrive/.local-tools/with-kaggle.py --script <abs>` (аналог with-github.py есть).
- raw-линки приватных репо дают 404 анонимно — «открытый доступ» только через публичное зеркало.
- gh quirks: `--log-failed` без деталей — качать артефакт `gh run download`.
- Merge-пуши с конфликтами: РАЗРЕШАТЬ ДО пуша — первый merge-пуш skillradar уехал с маркерами (исправлено bfd8ffb через минуту, но историю не переписывать).

## 3. Сборка Rust (КРИТИЧНО)
- PATH (Git Bash): mingw64 ПЕРВЫМ:
  `export PATH="/c/Users/omirb/.cache/mingw64/mingw64/bin:$HOME/.cargo/bin:$HOME/.rustup/toolchains/stable-x86_64-pc-windows-gnu/lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained:$PATH"`
- Флаги всегда: `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo build/test --jobs 1`.
- **Ловушки:** (1) OOM 3.4GiB → STATUS_STACK_BUFFER_OVERRUN / «invalid metadata» / «memory exhausted» → пауза/перезапуск, НЕ код-баг; «invalid metadata files for crate» → `cargo clean -p <crate>`; (2) exe держит target при живом сервере → `taskkill //F //IM ai-stazher-core.exe` (двойные слеши в Git Bash) перед cargo build; (3) raw-dylib dlltool — уносить tempfile-подобные зависимости; (4) несколько stale-серверов на порту дают «работает старая версия» — убивать ВСЕ (`netstat -ano | grep :ПОРТ`); (5) bin-цель с async fn — нужен явный tokio-рантайм в main(), иначе мгновенный exit 0; (6) блокирующие HTTP-клиенты (ureq) внутри async — только spawn_blocking (дедлок ловится интеграционным тестом с mock-LLM).

## 4. Тесты
- Rust: `cargo test --workspace --jobs 1` (atomic-flow: ~256+; skillradar core: 6+1 интеграционный).
- Python: `pytest backend/test_app.py` в venv.
- tsc: `node tools/tsc.js -p frontend/tsconfig.json` (node v24.22.1 в codex runtime `dependencies/node/bin/node.exe`; tsc standalone в skillradar/tools/, npm не нужен).
- CI: atomic-flow — GitHub Actions (rust.yml/surfaces.yml/fmt.yml); skillradar — ci.yml (rust+pytest+tsc).

## 5. Kaggle-протокол (токен 3, акк. umirbayulgaisha)
- Хелпер: `printf '<пароль>' | OneDrive/.venv/Scripts/python.exe OneDrive/.local-tools/with-kaggle.py --token-name Kaggle3_TOKEN --script <abs-path.py>` (kaggle CLI 2.2.5 в venv; авторизация KAGGLE_API_TOKEN env).
- Kernel: `kernels push -p <dir с kernel-metadata.json>`; статус: `kernels status owner/slug` (слаг = из URL после пуша, title реслагушивается!); выход: `kernels output owner/slug -p dir`.
- Dataset: `datasets create -p <dir с dataset-metadata.json + файлы>`; статус — **«ready»** (не «complete»!); файлы распаковываются плоско, маунт-лейаут: `/kaggle/input/datasets/<owner>/<slug>/...`; повторный create — skip, версии: `datasets version -p dir -m msg`.
- Скачивания обрываются → `curl -C -` resume; большие зипы проверять zipfile.testzip().
- Последовательные запросы, квоты до/после, никаких секретов в evidence, unknown не ретраится.
- hh.ru 403 на серверные IP (проверено локально и с Kaggle) — live-рынок только с браузера пользователя; в UI — честная пометка демо-снимка.

## 6. Параллельная codex-сессия — правила
- Работает в dev-копии И в OneDrive-копии; ветка `codex/studio-safe-zcode-20261104` (пушит в старый remote `github`).
- ПЕРЕД правками: `git branch --show-current`, `git log --oneline -3`, `git status --short`.
- Она коммитит поверх моих пушей и правит мои файлы ПОКА я работаю (durable_queue дополнился reservation_fence в процессе) — перечитывать файл перед каждым Edit; не коммитить её чужие untracked: `.atomic_flow/tree.lock`, `validation/core-corporate-review-20261024/`.
- Её работа: N01-N02 инкременты (af-evidence, /v1/capabilities, recovery-CLI), branch в github-remote.
- Субагенты упираются в user concurrency limit — последовательно.

## 7. Документы-протоколы (главные)
| Документ | Что в нём |
|---|---|
| `docs/ASSISTANT_HANDOFF.md` (OneDrive) | главный справочник порядка глав P06→P14/E00–E08, §7 матрица, §13 шаблон отчёта |
| `docs/PRODUCTION_ROADMAP.md` + `docs/PRODUCTION_PLAN.md` | P00–P14 планы |
| `docs/ENTERPRISE_CORE_PLAN.md` | E00–E08 |
| `docs/PRODUCTION_STATUS_2026-11-04.md/.json` | реестр 24 глав (NOT READY), следующие пакеты N01–N12 |
| `docs/PRODUCTION_INCREMENT_2026-11-04.md` | E00/E01+P09/E04 инкремент (codex) |
| `docs/POLYGLOT_RECONSTRUCTION_PLAN_2026-11-03.md` | карта переноса Rust/TS/Python, волны параллельных агентов |
| `docs/REAL_API_BENCHMARK_PROTOCOL.md` | live-модель: чистый SHA, квоты до/после, unknown не ретраится |
| `docs/ADR-0002-live-context-enrichment.md` | N05 дизайн: enrichment под бюджет-протоколом, решения D1–D6, слайсы S1–S3 |
| `docs/BETA_READINESS_CHECKLIST.md` | бета 300–500/96ч: T0 инцидент, T1 first-contact, T2 механика беты, T3 очередь, T4 enterprise-гэпы |
| `docs/ATOMIC_FLOW_PROTOCOLS_MASTER.md` | ЭТОТ документ |

## 8. Состояние (на 09.11.2026)
- **T0-инцидент (09.11, закрыт с остатками):** значение пароля vault побывало в публичном `r/main` через §0 этого документа; `atomic-flow_R` — PUBLIC (док ошибочно считал его private). Выполнено: скраб + force-push обеих веток (`e8b937b`), чистка OneDrive-копии, ротация пароля — **затем отменена владельцем: прежний пароль возвращён** (vault ре-шифрован обратно, верифицировано). Остаточные шаги: заявка в GitHub Support на purge unreachable-коммитов (SHA 7720171/5e9dd30/5f2815a/cecbb90), шеппинг `shared-access`, при случае — ротация токенов. Правило остаётся: значение пароля никогда не в коммитимых файлах/чате/логах.
- **atomic-flow_R (main=experimental=e8b937b):** Rust-линия полиглот-миграции. Готово: P00–P06 слайсы, P07 инженерный пилот (Python TaskRunner, отдельная приёмка), N01–N06 инженерные пакеты (af-evidence, af-budget, durable_queue, behavioral checker, интеграционный mock-LLM тест, delta-parity, «af task run»), Studio-дашборд v2.1, 256 тестов + Kaggle Linux 354/0. ADR-0002 (N05) утверждён, слайс S1 в работе. Открыто: N05 S1–S3, N07–N12 (Linux worker, installed release, corporate profile, live-грады) — внешние свидетельства. Бета: 300–500 мест, 96ч/участник, self-host — план в `docs/BETA_READINESS_CHECKLIST.md`.
- **Кодекс-сессия:** инкременты N01/N02/E04 (af-evidence, capabilities, recovery-CLI), ветка codex/studio-safe-zcode-20261104 (пушит в github-remote).
- **Хакатон (ЗАКРЫТ 09.11):** skillradar → hackathon-kz/...-31-atomic, main=5614f18+9a2475a. AI-стажёр сдан: ментор+Rust-агент+TS-студия+рынок hh.kz, 12 тестов, deck PDF, демо-видео 3:10 (OneDrive/Desktop/ai-stazher-demo.mp4 → владелец грузит на Google Диск). Дисквалификация-граница соблюдена: код atomic-flow не сдавался.
- **Память ассистента:** hackathon-skillradar.md (закрыт), atomic-flow-project-setup.md, ATOMIC_FLOW_PROTOCOLS.md, atomic-flow-b2b-roadmap.md.

## 9. Очередь дальше (по документам, без изменения планов)
1. N05: контекст с живой моделью — только по REAL_API_BENCHMARK_PROTOCOL (бюджет, аккаунт, SHA).
2. N03-доработка: admitted behavioral checker на host-адаптере (реальная сюита через JobRunner + JUnit-гейт — шаблон в skillradar/core behavioral_checker.rs).
3. N06 cutover: native FAIL→repair→fresh-check→publication на полном пути (нужен changeset resolve в Rust-сессии — codex ведёт reviewed_edit.rs).
4. N07–N12 — по мере появления внешних условий (Linux worker, installed release, live-грады).
