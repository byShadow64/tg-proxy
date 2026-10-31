# Сборка Android

Проект использует Kotlin и Jetpack Compose, поддерживает Android 8.0/API26
и новее. Текущая dev-версия — 0.1.8-dev, versionCode 10.

## Требования

- JDK 17.
- Android SDK Platform 36, Build Tools 35.0.0 и Platform Tools.
- Python 3 для подготовки и проверки исходников Helper.
- Gradle 8.13 через включённый wrapper.

Версии Gradle, Android Gradle Plugin, Kotlin и библиотек закреплены в проекте.
Wrapper проверяет SHA-256 дистрибутива; SSH-библиотеки проверяются задачей
`:core:verifySshArtifacts`. Не отключайте эти проверки для устранения ошибки сборки.

## Обычная сборка

Укажите SDK через Android Studio или локальный `android/local.properties`:

```properties
sdk.dir=/absolute/path/to/android-sdk
```

Из каталога `android/`:

```sh
./gradlew :core:verifySshArtifacts :app:verifyHelperPayload :core:test :app:testDebugUnitTest :app:assembleDebug :app:lintDebug
```

На Windows используйте `gradlew.bat`. Результат находится в
`app/build/outputs/apk/debug/app-debug.apk`. Первая сборка загружает зависимости.

Debug APK подходит для самостоятельной разработки. Он может иметь другую подпись,
чем установленное приложение, поэтому не следует использовать его для замены
своего основного профиля. Для обновления существующей установки нужна та же
подпись. Не удаляйте приложение и не очищайте его данные ради обхода ошибки подписи.
Ключи подписи и профили не входят в репозиторий.

## Windows: изолированный набор инструментов

Скрипт `scripts/build-local.ps1` использует существующий каталог
`TGProxyAndroidBuild` со структурой `sdk/` и `tools/jdk-*/`. По умолчанию он ищет
его в LocalAppData; произвольный путь задаётся явно:

```powershell
.\scripts\build-local.ps1 -ToolRoot "D:\AndroidBuild"
.\scripts\build-local.ps1 -ToolRoot "D:\AndroidBuild" -VerifyToolchainOnly
```

Скрипт не устанавливает системный JDK/SDK, не запускает эмулятор и не публикует APK.
Локальные настройки и отчёты сборки остаются вне исходников. Режим `-Delivery`
проверяет исходный сертификат dev-приложения и предназначен для владельца этого
ключа; для самостоятельной сборки используйте обычный debug-режим.

## Helper

В APK включён ограниченный набор исходников Helper с manifest размеров и хешей.
Gradle отклоняет отсутствующие, лишние и изменённые файлы. После изменения общего
Helper подготовьте assets из корня проекта:

```sh
python android/tools/prepare_helper_assets.py --source-root .
```

Не включайте в assets настройки сервера, пароли, ключи или локальные окружения.
Проверки инструментов подготовки:

```sh
python -m unittest discover -s android/tools -p "test_*.py"
```

Тесты редиректов встроенного Helper требуют Python-зависимости Helper.

## Тесты на Android

Запустите отдельный эмулятор API26 или новее и используйте его явный serial:

```sh
./gradlew :app:connectedDebugAndroidTest
```

Инструментальные тесты устанавливают приложение и тестовый APK. Используйте
выделенный эмулятор без личных данных. Отдельные проверки живой сети и обновления
требуют явного opt-in; обычный прогон их пропускает. Для проверки обновления
сохраняйте исходную подпись, профиль и защиту от отката версии.

Прохождение локальных тестов не заменяет проверку на реальном телефоне,
в Telegram и в используемой сети.
