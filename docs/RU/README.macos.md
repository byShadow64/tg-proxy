# TG Proxy для macOS

Исходный macOS entry point Flowseal сохранён. Этот fork пока публикует готовые сборки для Windows 10/11 x64; macOS DMG fork не выпускается.

## Запуск из исходников

Для интерфейса нужна сборка Python с поддержкой Tk. CustomTkinter и PyObjC устанавливаются из метаданных проекта.

```bash
git clone https://github.com/byShadow64/tg-proxy.git
cd tg-proxy
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/tg-ws-proxy-tray-macos
```

В Telegram Desktop добавьте MTProto-прокси `127.0.0.1:1443` с secret из настроек. [Подробности сборки](BuildFromSource.md).
