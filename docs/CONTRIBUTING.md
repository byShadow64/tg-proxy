# CONTRIBUTING

Спасибо за желание помочь TG Proxy (`byShadow64/tg-proxy`).

## Перед созданием issue

1. Проверьте README и документацию в `docs/README.md`.
2. Убедитесь, что похожий issue еще не открыт.
3. Создавайте issue и PR в `byShadow64/tg-proxy`.

## Как сообщать о проблемах

- Используйте шаблон `Problem report`.
- По возможности укажите:
  - версию приложения,
  - ОС,
  - шаги воспроизведения,
  - ожидаемое и фактическое поведение,
  - безопасный фрагмент журнала или текст ошибки без секретов и личных данных.

Чем точнее описание, тем быстрее можно помочь.

## Локальный запуск из исходников

Для разработки рекомендуется Python 3.11 в виртуальном окружении.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[build,helper-server]" pytest
```

На Linux используйте `.venv/bin/python` вместо `.venv/Scripts/python.exe`.

Запуск:

- консольный режим: `tg-ws-proxy`
- Windows tray: `tg-ws-proxy-tray-win`
- macOS tray: `tg-ws-proxy-tray-macos`
- Linux tray: `tg-ws-proxy-tray-linux`

Подробности: `docs/RU/BuildFromSource.md`.

## Проверки

Установите зависимости проекта и extra `helper-server`, затем запустите:

```bash
.venv/Scripts/python.exe -m pytest -q
```

Линтер (`ruff` настроен в `pyproject.toml`):

```bash
ruff check .
```

## Pull Request

Перед открытием PR:

1. Убедитесь, что изменение решает конкретную проблему.
2. Проверьте, что не сломаны существующие сценарии: запустите тесты и линтер.
3. Обновите документацию, если меняется поведение или настройка.

Небольшие и сфокусированные PR проверяются и принимаются быстрее.
