# Один проверенный пакет для двух каналов

Репозиторий исходников — `byShadow64/tg-proxy`. Windows, Publisher и Android
имеют независимые версии; [состояние подготовки](PROJECT_STATE.md) не заменяется
статусом GitHub Actions.

1. Подготовьте окончательные исходники, тесты, CHANGELOG и release notes.
2. Выполните необходимые проверки готового EXE/APK, профилей и обновления.
3. Сохраните точный source SHA, build SHA и SHA-256 каждого артефакта.
4. Для Windows создайте один immutable bundle с `source.zip`, `manifest.json`,
   notes и четырьмя assets. После проверок получите отдельный подписанный допуск.
5. Проверьте default branch, достижимость source SHA, успешный CI именно этого
   SHA, совпадение всех workflow и фактическое состояние тега/релиза.
6. Publisher передаёт подписанный data-only input draft и запускает ручной
   workflow trusted default branch. Read-only verify job проверяет вход;
   отдельный publish job повторяет проверки и загружает точные прежние bytes.
7. Сервер обновлений получает тот же Windows-пакет. В конце каждого канала
   скачайте конечные файлы и сравните размер и SHA-256.

## CI и публикация

`.github/workflows/windows-ci.yml` выполняет Python-тесты, bounded Android core
проверку и отдельную Windows verification build. Неподписанный CI-пакет не
становится релизом автоматически. В CI нет ключа издателя и права записи Contents.

`.github/workflows/build.yml` запускается только вручную на trusted default branch.
Он не собирает EXE, не запускает входной код и не импортирует проект из bundle.
Только этот проверенный Actions context может создать отсутствующий stable-тег.
Существующие теги и опубликованные файлы не передвигаются и не перезаписываются.

Никаких channel rebuild, force push, retag, clobber, старого tag-trigger выпуска
или слепого повторного dispatch. Неоднозначный ответ проверяется по удалённому
состоянию. Конфликт тега, assets, источников или прав блокирует зависимый шаг.
Очередь, draft и dispatch не означают успешную публикацию.

Для смены только source-снимка нужны новый source SHA, проверка соответствия
сохранённому EXE и новый допуск. Исторический bundle не переписывается.
Staging и инструментированные тестовые приложения не допускаются в каналы.

Подробности: [Publisher](PUBLISHER.md), [работа с GitHub](CODEX_GITHUB.md),
[публичные материалы](GITHUB_CONTENT_POLICY.md).
