# TG Proxy для Linux

Этот fork публикует готовый Windows EXE и архив Ubuntu helper. Linux tray/CLI entry point сохранены в исходниках; пакеты `.deb`, `.rpm` и AUR этой версии fork не публикуются.

## Запуск из исходников

```bash
git clone https://github.com/byShadow64/tg-proxy.git
cd tg-proxy
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/tg-ws-proxy-tray-linux
```

Для графического интерфейса нужны Tk и поддержка системного трея/AppIndicator. Консольный прокси запускается командой `.venv/bin/tg-ws-proxy`.

В Telegram Desktop добавьте MTProto-прокси `127.0.0.1:1443` с secret из настроек. Настройки и аргументы описаны в [BuildFromSource.md](BuildFromSource.md).

Для VPS используйте отдельный [helper и systemd-unit](Helper.md). Его endpoint TLS v2 работает на `8444/tcp` и требует токен и проверку отпечатка сертификата на Windows-клиенте.
