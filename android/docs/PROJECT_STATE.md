# Android: состояние и проверки

30.10.2026 локально проверена **0.1.7-dev / code 9**. APK: **12 076 782 байта**,
SHA-256 `3ac755a52d010587e0405ab761c344a5f1a6ab26a62e37f4c54ec3c8fc6e4403`.
Сохранены пакет `io.github.byshadow64.tgproxy`, исходная dev-подпись, ключ
установки, профиль и подписанный канал обновления. Встроенный Helper содержит
27 проверяемых файлов нового проекта, включая ограничение адресов Telegram.

Выполнены свежие 143 core-теста (1 opt-in пропущен), 28 JVM-тестов приложения,
6 Python-тестов Helper и 18 Python-тестов публикации; lint: 0 ошибок, 58 warnings.
На API26/API36 прошли по 48 Compose-проверок с искусственным состоянием.
Отдельные native-прогоны точного release APK: 19/20 passed, по 6 opt-in skips.
Оригинальная 0.1.6/code8 обновилась до точной code9 на обоих API без удаления:
сохранены шифротекст, настройки, секрет и ключ установки. Проверены фоновые
сервисы/Stop, ссылки, enrollment с локальным TLS, фактические assets Helper,
updater guards и очистка partial. После UI-прогонов восстановлен production APK,
его установленный SHA-256 и сохранность профиля повторно сверены. Оба AVD
остановлены, userdata сохранены.

Полный production updater download/PackageInstaller UI E2E для code9 не повторялся:
его код, origin и криптографические проверки не менялись. Живые внешние Helper,
Telegram-аккаунт, скорость медиа, физические Xiaomi/Samsung и долгий Doze в этой
задаче не проверялись. Новая GitHub CI/публикация не подтверждаются этими локальными
результатами. Initial commit назначает root; source snapshot и private receipts
сохранены отдельно. Android не входит в Windows release assets.

Актуальные версия, source/build SHA, APK hash, выполненные проверки и их границы
собраны в [состоянии проекта](../../docs/PROJECT_STATE.md).

Пользовательские инструкции: [Android](../README.md),
[сборка](../BUILDING.md), [обновления](ANDROID_UPDATES.md).
Android остаётся отдельной dev-версией и не входит в Windows release assets.
