# Android changelog

## 0.1.7-dev / code 9 — 2026-10-30

- Move the embedded public Helper's project identity and documentation references
  to the standalone `byShadow64/tg-proxy` project. Keep the Android package,
  original development signer, encrypted profile, installation key and signed
  update origin unchanged.
- Include the reviewed Telegram-only admission checks: foreign proxy protocols
  and unsupported data-center identifiers are rejected before route selection
  or Helper lease lookup. Supported Telegram protocols and media routes remain
  available; this is not a device firewall or inspection of encrypted messages.
- Package the complete 27-file Helper payload, including destination bounds and
  fail-closed upstream redirect handling. Build and runtime manifest/hash checks
  continue to reject missing, extra or altered payload files.
- Add an exact original 0.1.6/code8 to 0.1.7/code9 migration check for encrypted
  settings, local secret and the per-install non-exportable device key.
- Retain the owner logo, green launcher, Dev notice, screenshots, RU/EN Help,
  Telegram chooser, Copy link and Android-confirmed update installation.

Validation and artifact identity are recorded separately in PROJECT_STATE.
These changes do not establish physical Xiaomi/Samsung behavior, Telegram
account/media speed or long Doze reliability.

## 0.1.6-dev / code 8 — 2026-10-29

- Rename the connection action to “Open in Telegram” while retaining the Android app chooser and Copy link.
- Replace the dense Help page with a short connection guide and expandable troubleshooting, background and optional Helper topics.
- Report an unsuccessful route candidate as information; reserve the warning for failure of the whole connection attempt.
- Forward available WSS/Helper binary payload prefixes without waiting to fill a 64 KiB block; keep framing, TLS and size checks intact.
- Cool down unanswered routes after a real setup deadline without penalizing queued work or cancelled race losers.
- Add a separately signed Android development update channel, bounded verified downloads and Android-confirmed installation. Scheduled checks and unmetered Wi-Fi downloads can be disabled.
- Validate update package, version, original APK signer, SHA-256 and size; retain local settings across updates. No silent installation or Windows update-channel change.


Android and Windows versions are independent. This is local development,
not a public stable APK. Counts and final checks: [PROJECT_STATE](docs/PROJECT_STATE.md).

## 0.1.5-dev / code 6 — reliability and interface audit, 2026-10-29

- Fixed intermittent Helper enrollment rejection caused by subsecond server/client
  clock differences rounding a 60-second challenge to 61 seconds. The client now
  permits a bounded 30-second clock allowance; expired or excessively future
  challenges still fail, and server expiry, TLS and signature checks remain intact.
- Fixed Apply and restart: successful persistence releases the save guard before
  restarting the service. Invalid settings cannot invoke the restart callback.
  Overview shows the applied listener port while running, rather than a saved
  port that has not been applied yet.
- TCP connection setup tries up to eight distinct DNS addresses within one
  DNS/TCP/TLS deadline. An unreachable first address no longer discards the rest
  of the answer. TLS identity and pin failures remain fatal; no insecure fallback
  or replay of user traffic was introduced.
- Stop closes owned sockets immediately and uses one bounded worker-join budget
  instead of accumulating separate waits. Late connector results are discarded
  without route events, counters or relay payload after the session is retired.
- Obsolete, missing and stale foreground-service requests now finish safely
  after foreground acknowledgement. They cannot reconstruct absent SSH jobs or
  credentials. Active SSH setup also blocks a conflicting proxy start.
- Simplified Overview: compact owner-logo header, Start/Stop, connection links,
  then statistics. External-link import remains in Connection and Help. The
  original logo, green launcher, screenshots and development notice are retained.
- Preserved unsaved local-port edits when a verified Helper profile arrives,
  while taking all hidden server credentials from that verified profile. Helper
  sharing now sits with the saved server; a previous success no longer appears
  to verify a different typed IP.
- Restored access to an active SSH setup after switching tabs. Public registered
  access is unchecked by default; key confirmation and both access/upgrade
  consents are bound to the selected server and SSH key. Leaving the setup screen
  clears the password. Help displays the actual build version.
- Added regression coverage for multi-address TLS setup, stalled connector Stop,
  actual save/restart, malformed foreground starts, settings drafts and SSH
  consent. Added an original code 5 → code 6 migration test. Completed execution
  results and remaining limits are recorded separately in PROJECT_STATE.

This update does not claim a measured speed increase, a confirmed fix for a
specific Samsung/Xiaomi network or proof of account/media operation and long
Doze. Windows, Publisher, Staging and their update channels are unchanged.

## 0.1.4-dev/code5 — connection link actions,29.10.2026

- Added **Open link** and **Copy link** in Overview, without client-specific
  configuration. Android selects the app for a `tg://proxy` link; copying uses
  the equivalent HTTPS Telegram link.
- Both actions use the applied running listener's local port and secret,
  never pending settings. They are disabled while stopped or transitioning;
  runtime guards reject a late action after Stop.
- Copied connection links are marked sensitive and never written to the journal
  or saved UI state. Each phone generates its own local connection link.
- Updated RU/EN labels and Help. Existing Helper IP-only setup, launcher, owner
  logo and Dev notice remain intact.
- Reviewed the current archived upstream at `540e588d15fbdf806f694fbe0b952ff044d39a07`.
  Link formats match; no GPL code was copied and authenticated TLS was preserved.
  This update does not claim a speed advantage or a physical-device stability fix.
- Host100core/1opt-in skip (unchanged cached core),23app JVM/lint, API36 UI32
  and actual action-service2 on both API26/API36 passed. Original-signer and
  independent artifact audit passed; private-delivery and live-network receipts
  remain separate. See [PROJECT_STATE](docs/PROJECT_STATE.md).
- Windows stable, Publisher, Staging and their update channels were not changed.

## 0.1.3-dev/code4 — local verified development,28.10.2026

Exact development APK verified on API26/API36; physical-device outcomes and
private delivery/shutdown remain separate states.

- Helper screen simplified to IP+Connect. Existing private profiles remain usable;
  on/off and local-port Save preserve their hidden secrets. No owner-code/token/
  pin form is required for a ready registered Helper.
- IP-only Helper links now have a local preview and explicit confirmation.
  External Telegram MTProxy links open Telegram and never become Helper.
  Local127.0.0.1/secret links remain specific to each phone.
- RU/EN Help with Telegram setup, notification settings, manual battery/background
  guidance for Samsung/OneUI and Xiaomi/HyperOS; no automatic system-policy change.
- Foreground RAM-only enrollment with90s Cancel/deadline and per-request socket
  cleanup. Short network wake windows45/60/65s replace perpetual idle wake;
  strict CA/pin/central signed lease checks remain unchanged.
- Handshake diagnostics distinguish categories while preserving invalid-secret
  rejection without upstream. SECRET_OR_PROTOCOL does not uniquely identify a
  wrong secret; stale Telegram record/protocol also need checking.
- User confirms0.1.2 messages/media work on Xiaomi. Background Helper and SamsungS24
  ping reports remain unverified on those phones. Traffic complaint was withdrawn
  as a mistake, so no traffic-bug fix is claimed.
- Exact local proof:100core/1opt-in skip+23app/lint;31 Compose and12 release
  cases per OS on API26/36, original0.1.2 upgrade without clear/uninstall,
  all five DC direct ordinary/media20/20, real registered Helper afterHome
  on both APIs. Production EN MainActivity link dialog passed on API36.
- Idle regression passed both APIs. Exact API36 UID20s RX0/TX0; bounded sample,
  not zero-traffic/OEM Doze guarantee. Native captures/cleanup finalize separately.

## Historical versions

The statements below describe evidence available at their release checkpoint;
new user observations and current candidate limits are above.

## 0.1.2-dev / code3 — локально проверено, 2026-10-28

Локальный exact APK с payload063bf… проверен; физический Xiaomi/аккаунт/медиа
остаются неподтверждёнными. Это development, не публичный stable.

- После повторного отрицательного теста 0.1.1 на Xiaomi (Wi-Fi, Helper выключен)
  исправлены последовательные долгие попытки соединения и удержание slots
  отключившимися клиентами. До четырёх ограниченных попыток direct/CF:443,
  восьмисекундный бюджет, строгий TLS, WS ping и ограниченный DNS.
- Реализован registered-client Helper по IP: отдельный P-256 ключ
  установки в Keystore, доверенный центральный descriptor и короткий lease в
  RAM. Старый private bearer не выдаётся; это не HWID/аттестация приложения.
- Настройка неизвестного Helper через настоящий SSH/SFTP: host key до root-пароля,
  manifest/receipt/central lease; отдельное согласие перевода private сервера.
  RAM-only foreground dataSync задача, прогресс и отмена без обещания удалённого отката.
- В шапке исходный логотип владельца 48dp; зелёная launcher-иконка сохранена.
- Добавлена компактная пометка о dev-версии на русском и английском; разрешены
  скриншоты приложения, маскирование паролей и токенов сохранено.
- Публичные анонимные пробы дали 23/26: automatic 4/4, CF 8/8, fixed 6/6,
  DNS 4/4, forced fronted 1/4. Это не проверка аккаунта/медиа или сети телефона.
  Эта прежняя матрица не подменяет новую default-runtime проверку exact APK.

- Исправлены startId/cancel foreground setup, контраст pill, direct+relay/WSS
  status. Host95core/1skip+15app; actual default direct16/16 наAPI26/36,
  включая numeric DNS media fallback. Exact 0.1.1→0.1.2 upgrade, release7 и
  live registry/Helper resPQ прошли на обоих API, SSH setup — на API36.
  Compose18 и Home/notification Cancel повторены на обоих API; телефон не проверен.
- Embedded Helper whole-FIN/FIFO исправлен после реального Telegram A/B;
  registered frames не пустые и учитываются минимум как4KiB в ресурсной квоте.
  Payload26/215040 bytes063bf… сверён с exact APK; renewal hook имеет0750.

## 0.1.1-dev — 2026-10-27

- После отрицательной проверки 0.1.0-dev на Xiaomi 17 Ultra исправлены
  подтверждённые ограничения ядра. Повторная проверка нового APK на телефоне
  остаётся обязательной; доставка сообщений и скорость медиа не объявляются проверенными.
- Лимит по умолчанию 32 соединения вместо 8, ограниченные очереди и общий
  16 MiB бюджет packet coalescing. Восстановлены desktop-правила ef/ee/dd,
  quick ACK и padding; пакеты до 1 MiB + 19 объединяются, большие длины
  переходят в ограниченный поток без резервирования объявленного размера.
- Убран ошибочный 120-секундный idle-таймер каждого направления. Сохранены
  пределы handshake, записи и начатого кадра; первый ответ после полного
  клиентского пакета ожидается до 20 секунд.
- Отдельные попытки WSS больше не закрывают всю сессию при своём timeout.
  DNS/fixed/строгий SNI-резерв и cache отдельно для DC/медиа; предпочтение
  подтверждается реальными входящими данными. Пользовательские пакеты не переигрываются.
- Добавлено подключение собственного Helper по IP и одноразовому SSH-коду:
  certificate-bound HMAC, строгий JSON/base64url, сохранение только проверенных
  pin/токена. Ручной TLS-pinned Helper сохраняет исключительный маршрут.
- Зелёная adaptive-иконка; прозрачное адаптивное уведомление с одной Stop-кнопкой
  в каждом состоянии, без дублирования действия. Журнал использует текущую версию.
  UI/Keystore/обновление из 0.1.0 и native Stop проверены на AOSP API 26/36.
- Готовая APK nondebuggable, без debug tooling/test harness; прежний development
  сертификат сохраняет профиль при обновлении. Это development, не Android stable.
- Реальный Android AppRuntime/ProxyService прошёл owner-code enrollment и
  анонимный Helper req_pq_multi/resPQ на API 26/36 с восстановлением прежних настроек.
- Python и native local-engine req_pq_multi/resPQ на ПК независимо дали 13/14
  успешных комбинаций. DC2 media + SNI-reserve не ответил; этот результат не
  переносится на сеть телефона и не подтверждает реальные аккаунты/файлы.

## 0.1.0-dev — 2026-10-27

- Нативный интерфейс Kotlin/Compose: обзор, маршруты, журнал; RU/EN, светлая/тёмная тема.
- Локальный MTProto listener только на loopback, пользовательский foreground-сервис,
  уведомление с остановкой и явное подключение установленного Telegram.
- Обфускация MTProto ef/ee/dd с векторами совместимости Python; прямой TLS/WSS
  и защищённый Helper v2 с проверкой pin до токена.
- Потоковая обработка по 64 KiB, ограниченные сессии, очереди, DNS и тайм-ауты;
  остановка закрывает незавершённые handshake и активные соединения.
- Настройки AES-GCM/Android Keystore без переноса Windows-профиля или реальных
  реквизитов; запрет backup, скрытые секреты и обезличенный ограниченный журнал.
- Проверки криптографии, локальных TLS/WSS, неверного pin/авторизации,
  валидации настроек и жизненного цикла. Проверка Android выявила и исправила
  повторное занятие порта после остановки и гонки быстрых start/stop/restart.

Доставка сообщений реальным аккаунтом Telegram и длительная работа на физических
телефонах пока не объявляются проверенными. Автообновление, CF/Worker/H2,
fake TLS, SSH-установка и VPN в эту версию не входят.
