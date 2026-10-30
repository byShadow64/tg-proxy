"""The separate publisher UI. It never builds or modifies a client executable."""
from __future__ import annotations

import json
import secrets
import threading
import time
import webbrowser
from dataclasses import replace
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from publisher import __version__
from publisher.bundle import export_bundle, load_bundle
from publisher.controller import JobRunner, safe_code
from publisher.profiles import (ProfileStore, ServerCredentials, ServerProfile,
                                credentials_from_dict, credentials_to_dict,
                                default_keys_path, load_default_profile,
                                validate_profile)
from publisher.state import PublicationState
from proxy.project import REPOSITORY
from ui.ctk_theme import apply_ctk_appearance, ctk_theme_for_platform, install_window_icon
from ui.icons import icon_image


PHASES = {
    "loading": "Проверяю пакет", "approval": "Подтверждаю готовность пакета",
    "connecting": "Подключаюсь", "connect": "Подключаюсь", "preflight": "Проверяю назначение",
    "upload": "Загружаю файлы", "uploading": "Загружаю файлы", "readback": "Сверяю загруженные файлы",
    "verifying": "Проверяю файлы", "verify": "Проверяю файлы", "public_verification": "Проверяю публичное скачивание",
    "github": "Передаю пакет GitHub", "github_upload": "Загружаю пакет GitHub",
    "server": "Публикую на сервере", "dispatch": "Запускаю workflow GitHub",
    "rate_limit": "GitHub ограничил частоту запросов", "waiting": "Ожидаю разрешённого времени запроса",
    "complete": "Операция завершена", "published": "Публикация завершена",
}
STATUSES = {
    "published": "Опубликовано и проверено", "published_and_verified": "Опубликовано и проверено",
    "already_published": "Уже опубликовано; файлы совпадают", "queued": "Передано в GitHub Actions",
    "draft": "Подготовлен черновик", "draft_ready": "Черновик готов; workflow ещё не запущен",
    "dispatch_unconfirmed": "Черновик готов; запуск workflow не подтверждён. Проверьте результат",
    "not_published": "Публикация пока не найдена", "pending": "Проверка ещё не завершена",
    "verification_pending": "Файлы опубликованы; проверка не завершена",
    "published_verification_pending": "Файлы опубликованы; проверка не завершена",
    "publication_unconfirmed": "Сервер мог принять обновление; проверьте результат",
    "different_version": "В канале сейчас другая версия", "failed": "Не завершено",
    "cancelled": "Отменено", "ready": "Соединение проверено",
}
ERRORS = {
    "operation_failed": "Операция не завершена. Подробности не содержат реквизитов.",
    "cancelled": "Операция отменена.", "token": "Укажите токен GitHub.",
    "authentication": "Не удалось войти. Проверьте реквизиты; повторный вход выполняется вручную.",
    "unauthorized": "GitHub не принял токен. Повторный вход выполняется вручную.",
    "permission": "Недостаточно прав GitHub для этого действия.",
    "forbidden": "GitHub не разрешил действие. Проверьте права токена.",
    "rate_limited": "GitHub ограничил частоту запросов. Повторите после указанной паузы.",
    "rate_limit": "GitHub ограничил частоту запросов. Повторите после указанной паузы.",
    "approval": "Сначала подтвердите готовность проверенного пакета.",
    "approval_missing": "Сначала подтвердите готовность проверенного пакета.",
    "approval_required": "Сначала подтвердите готовность проверенного пакета.",
    "signing_key": "Не удалось использовать ключ издателя. Укажите настроенный на этом ПК файл DPAPI.",
    "legacy_profile": "Файл ключей издателя недоступен или имеет другой формат.",
    "secret_store": "Сохранённые реквизиты недоступны этому пользователю Windows.",
    "profile": "Проверьте адрес HTTPS, SSH, порт, каталог и отпечаток сервера.",
    "host_key_mismatch": "Ключ SSH не совпал. Проверьте сервер перед новым подключением.",
    "https": "Не удалось подтвердить HTTPS-соединение с сервером.",
    "public_verification": "Загрузка завершена, но публичное скачивание не подтверждено. Проверьте результат.",
    "publication_unconfirmed": "Ответ сервера при активации обновления потерян. Сначала нажмите «Проверить результат».",
    "history_store": "Не удалось сохранить локальную историю. Проверьте результат публикации отдельно.",
    "bundle_required": "Сначала выберите готовый пакет публикации.",
    "bundle_changed": "Пакет изменился после проверки. Заново выберите исходный проверенный набор.",
    "asset_hash": "Файлы не совпадают с манифестом. Нужен исходный проверенный пакет.",
    "source_hash": "Архив исходников не совпадает с манифестом.",
    "authentication_required": "GitHub не принял токен. Вход и обновление реквизитов выполняются вручную.",
    "invalid_token": "Проверьте формат токена GitHub.",
    "permission_or_rate_limit": "GitHub не разрешил действие. Проверьте права доступа.",
    "trusted_workflow_not_deployed": "Сначала внедрите новый workflow в основную ветку GitHub.",
    "successful_trusted_ci_required": "Для выбранного коммита ещё не подтверждён успешный CI GitHub.",
    "immutable_version": "На сервере уже есть другие файлы этой версии. Нужен новый номер версии.",
    "conflict": "Обнаружен конфликт версии или файлов. Публикация другого канала остановлена.",
}
HARD_CONFLICTS = frozenset({"immutable_version", "downgrade", "asset_manifest_mismatch", "asset_conflict",
                            "release_conflict", "latest_downgrade", "tag_conflict", "release_notes_conflict",
                            "bundle_changed", "approval_identity"})


class PublisherApp(ctk.CTk):
    def __init__(self, *, bundle_path=None, keys_path=None, appearance="dark", store=None, receipts=None):
        apply_ctk_appearance(ctk, appearance)
        super().__init__()
        self.title(f"TG Proxy Publisher — {__version__}")
        self.geometry("960x740")
        self.minsize(860, 640)
        install_window_icon(self, default=True)
        self.theme = ctk_theme_for_platform()
        self.configure(fg_color=self.theme.bg)
        self.runner, self.bundle, self.approval = JobRunner(), None, None
        self.activation_requested = threading.Event()
        self._closing, self._completion = False, None
        self._controls, self._last_results = [], {}
        self._last_link, self._last_phase, self._animation = "", "", False
        self._github_cooldown_until = 0.0
        self.store, self.receipts = store or ProfileStore(), receipts or PublicationState()
        self._store_valid = True
        try:
            self.profiles, self.saved, self.active_id = self.store.load()
        except Exception:
            self.profiles, self.saved, self.active_id = [ServerProfile()], {}, "default"
            self._store_valid = False
        had_saved_credentials = bool(self.saved.get("github_token") or self.saved.get("servers"))
        if keys_path:
            try:
                imported = load_default_profile(keys_path)
                self.profiles = [imported] + [p for p in self.profiles if p.profile_id != "default"]
                self.saved.setdefault("servers", {}).setdefault("default", {})["legacy_key_path"] = str(keys_path)
            except Exception:
                pass
        self.remember = ctk.BooleanVar(value=had_saved_credentials)
        self.confirmed = ctk.BooleanVar(value=False)
        self.want_server, self.want_github = ctk.BooleanVar(value=True), ctk.BooleanVar(value=True)
        self._build()
        self._select_profile(self.active_id)
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(60, self._poll)
        if not self._store_valid:
            self._log("Настройки не прочитаны. Работа в памяти; исходный файл сохранён без изменений.")
        if bundle_path:
            self.after(150, lambda: self._load_path(bundle_path))

    def _control(self, widget, *, normal="normal"):
        self._controls.append((widget, normal))
        return widget

    def _button(self, parent, text, command, *, primary=False, icon=None):
        theme = self.theme
        widget = ctk.CTkButton(parent, text=text, command=command, height=34, corner_radius=8,
                               font=(theme.ui_font_family, 12, "bold"),
                               fg_color=theme.accent if primary else theme.accent_soft,
                               hover_color=theme.accent_hover if primary else theme.field_border,
                               text_color=theme.on_accent if primary else theme.accent,
                               image=icon_image(icon, theme, 16, color="on_accent" if primary else "accent") if icon else None)
        return self._control(widget)

    def _entry(self, parent, label, *, value="", secret=False):
        wrapper = ctk.CTkFrame(parent, fg_color="transparent")
        wrapper.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(wrapper, text=label, anchor="w", font=(self.theme.ui_font_family, 12),
                     text_color=self.theme.text_secondary).pack(fill="x")
        entry = self._control(ctk.CTkEntry(wrapper, height=34, show="•" if secret else "",
                                         font=(self.theme.ui_font_family, 12)))
        entry.pack(fill="x")
        entry.insert(0, value)
        return entry

    def _build(self):
        theme = self.theme
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=24, pady=(20, 12))
        ctk.CTkLabel(header, text="TG Proxy Publisher", font=(theme.ui_font_family, 25, "bold"),
                     text_color=theme.text_primary).pack(anchor="w")
        ctk.CTkLabel(header, text="Один проверенный пакет для GitHub и сервера обновлений",
                     text_color=theme.text_secondary).pack(anchor="w", pady=(2, 0))
        self.tabs = ctk.CTkTabview(self, fg_color=theme.surface)
        self.tabs.pack(fill="both", expand=True, padx=20)
        for name in ("Пакет", "Назначения", "Публикация", "Журнал"):
            self.tabs.add(name)
        self._build_bundle(self.tabs.tab("Пакет"))
        self._build_targets(self.tabs.tab("Назначения"))
        self._build_publish(self.tabs.tab("Публикация"))
        self.journal = ctk.CTkTextbox(self.tabs.tab("Журнал"), font=(theme.mono_font_family, 11),
                                     wrap="word", state="disabled")
        self.journal.pack(fill="both", expand=True, padx=8, pady=8)
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=24, pady=(12, 18))
        self.status = ctk.CTkLabel(footer, text="Выберите готовый пакет публикации", anchor="w")
        self.status.pack(fill="x")
        row = ctk.CTkFrame(footer, fg_color="transparent")
        row.pack(fill="x", pady=(4, 0))
        self.bar = ctk.CTkProgressBar(row, height=6, progress_color=theme.accent)
        self.bar.pack(side="left", fill="x", expand=True, padx=(0, 12))
        self.bar.set(0)
        self.cancel_button = ctk.CTkButton(row, text="Отменить", width=100, height=28,
                                          command=self._cancel, state="disabled")
        self.cancel_button.pack(side="right")

    def _build_bundle(self, page):
        row = ctk.CTkFrame(page, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=12)
        self.path_label = ctk.CTkLabel(row, text="Папка publication не выбрана", anchor="w",
                                      wraplength=630, text_color=self.theme.text_secondary)
        self.path_label.pack(side="left", fill="x", expand=True, padx=(0, 12))
        self._button(row, "Выбрать пакет", self._choose_bundle).pack(side="right")
        self.bundle_summary = ctk.CTkLabel(page, text="Нужны manifest.json, source.zip, RELEASE_NOTES.md и assets.",
                                          anchor="w", justify="left", font=(self.theme.ui_font_family, 16, "bold"))
        self.bundle_summary.pack(fill="x", padx=12, pady=8)
        self.bundle_details = ctk.CTkTextbox(page, height=180, font=(self.theme.mono_font_family, 11),
                                            state="disabled", wrap="word")
        self.bundle_details.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        check = self._control(ctk.CTkCheckBox(page, text="Сборка протестирована; разрешаю публикацию этого пакета",
                                             variable=self.confirmed))
        check.pack(anchor="w", padx=12, pady=(0, 12))
        row = ctk.CTkFrame(page, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=(0, 12))
        self._button(row, "Подтвердить готовность", self._approve, primary=True, icon="check").pack(side="left")
        self._button(row, "Экспорт для workflow", self._export, icon="download").pack(side="left", padx=12)
        self.approval_label = ctk.CTkLabel(page, text="Выбор пакета не разрешает публикацию автоматически.",
                                          anchor="w", text_color=self.theme.text_secondary)
        self.approval_label.pack(fill="x", padx=12, pady=(0, 10))

    def _build_targets(self, page):
        form = ctk.CTkScrollableFrame(page, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=8, pady=8)
        ctk.CTkLabel(form, text="GitHub", font=(self.theme.ui_font_family, 17, "bold")).pack(anchor="w")
        self.repository = self._entry(form, "Репозиторий", value=REPOSITORY)
        self.token = self._entry(form, "Токен GitHub", value=self.saved.get("github_token", ""), secret=True)
        ctk.CTkLabel(form, text="Для передачи workflow нужны Contents: write и Actions: write. Вход выполняется вручную.",
                     anchor="w", justify="left", wraplength=780, text_color=self.theme.text_secondary).pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(form, text="Сервер обновлений", font=(self.theme.ui_font_family, 17, "bold")).pack(anchor="w")
        row = ctk.CTkFrame(form, fg_color="transparent")
        row.pack(fill="x", pady=(6, 12))
        self.profile_menu = self._control(ctk.CTkOptionMenu(row, values=[self._profile_label(p) for p in self.profiles],
                                                          command=self._select_profile_name, width=260))
        self.profile_menu.pack(side="left")
        self._button(row, "Другой сервер", self._new_profile).pack(side="left", padx=12)
        self._button(row, "Сохранить настройки", self._save_settings).pack(side="left")
        ctk.CTkLabel(form, text="Выбор сервера меняет только место загрузки. Адреса у клиентов остаются прежними.",
                     anchor="w", justify="left", wraplength=780, text_color=self.theme.text_secondary).pack(fill="x", pady=(0, 12))
        self.fields = {}
        for key, label in (("name", "Название профиля"), ("base_url", "Базовый адрес HTTPS"),
                           ("host", "Адрес SSH / SFTP"), ("port", "Порт SSH"),
                           ("username", "Пользователь SFTP"), ("webroot", "Каталог публикации SFTP"),
                           ("host_key", "Доверенный отпечаток SSH (SHA256:...)")):
            self.fields[key] = self._entry(form, label)
        self._button(form, "Получить отпечаток SSH", self._probe, icon="shield").pack(anchor="w", pady=(0, 14))
        ctk.CTkLabel(form, text="Способ входа", anchor="w").pack(fill="x")
        self.auth = self._control(ctk.CTkOptionMenu(form, values=["Настроенный ключ этого ПК", "Файл SSH-ключа", "Пароль"]))
        self.auth.pack(anchor="w", pady=(0, 12))
        self.credential_fields = {}
        for key, label, secret in (("private_key_path", "Путь к SSH-ключу", False),
                                    ("password", "Пароль SSH / SFTP", True),
                                    ("key_passphrase", "Пароль SSH-ключа", True),
                                    ("legacy_key_path", "Файл ключей издателя (DPAPI этого пользователя)", False)):
            self.credential_fields[key] = self._entry(form, label, secret=secret)
        self._button(form, "Выбрать файл ключей издателя", self._choose_keys).pack(anchor="w", pady=(0, 12))
        self._control(ctk.CTkCheckBox(form, text="Запомнить реквизиты в Windows (DPAPI)", variable=self.remember)).pack(anchor="w", pady=(0, 10))
        self._button(form, "Проверить выбранные назначения", self._check_targets, icon="connection").pack(anchor="w", pady=(6, 12))

    def _build_publish(self, page):
        ctk.CTkLabel(page, text="Куда передать этот пакет", font=(self.theme.ui_font_family, 19, "bold")).pack(anchor="w", padx=16, pady=(20, 16))
        for text, variable in (("Сервер обновлений — публикация и проверка скачивания", self.want_server),
                                ("GitHub — проверенный пакет в черновик и запуск workflow", self.want_github)):
            self._control(ctk.CTkCheckBox(page, text=text, variable=variable)).pack(anchor="w", padx=16, pady=8)
        ctk.CTkLabel(page, text="Каждый канал имеет собственный результат. Если GitHub недоступен, успешная публикация на сервере сохраняется.\n"
                               "GitHub Actions запускается только по вашему действию. Передача workflow ещё не означает публикацию релиза.",
                     anchor="w", justify="left", wraplength=790, text_color=self.theme.text_secondary).pack(fill="x", padx=16, pady=16)
        self.channel_labels = {}
        for channel, title in (("server", "Сервер"), ("github", "GitHub")):
            self.channel_labels[channel] = ctk.CTkLabel(page, text=title + ": не проверялось", anchor="w", justify="left", wraplength=780)
            self.channel_labels[channel].pack(fill="x", padx=16, pady=8)
        row = ctk.CTkFrame(page, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=20)
        self._button(row, "Опубликовать выбранное", self._publish, primary=True, icon="download").pack(side="left")
        self._button(row, "Проверить результат", self._verify_results, icon="check").pack(side="left", padx=12)
        row = ctk.CTkFrame(page, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=2)
        self._button(row, "Открыть GitHub Actions", self._open_result, icon="globe").pack(side="left")
        self._button(row, "Скопировать отчёт", self._copy_report, icon="copy").pack(side="left", padx=12)

    def _choose_bundle(self):
        path = filedialog.askdirectory(parent=self, title="Выберите папку publication")
        if path:
            self._load_path(path)

    def _load_path(self, path):
        if self.runner.busy or self._closing:
            return
        self.bundle, self.approval, self._last_results, self._last_link = None, None, {}, ""
        self.confirmed.set(False)
        self.path_label.configure(text=str(path))
        self.bundle_summary.configure(text="Пакет пока не подтверждён")
        self.approval_label.configure(text="Выбор пакета не разрешает публикацию автоматически.")
        self.bundle_details.configure(state="normal")
        self.bundle_details.delete("1.0", "end")
        self.bundle_details.configure(state="disabled")
        def work(emit, cancel):
            bundle = load_bundle(path)
            from publisher.trust import load_approval
            try:
                approval = load_approval(bundle)
            except Exception:
                approval = None
            sizes = {name: asset.stat().st_size for name, asset in bundle.assets.items()}
            return bundle, approval, sizes
        def complete(result):
            bundle, approval, sizes = result
            self.bundle, self.approval = bundle, None
            self.confirmed.set(False)
            self.path_label.configure(text=str(bundle.root))
            self.bundle_summary.configure(text=f"TG Proxy {bundle.version} · 4 файла · целостность подтверждена")
            details = ["Пакет: " + bundle.bundle_id, "Исходники: " + bundle.source_commit, "Сборка: " + bundle.build_commit, ""]
            for name, asset in bundle.assets.items():
                details.extend([f"{name}  ({sizes[name]:,} байт)", bundle.manifest["assets"][name]])
            details.extend(["", bundle.notes])
            self.bundle_details.configure(state="normal")
            self.bundle_details.delete("1.0", "end")
            self.bundle_details.insert("1.0", "\n".join(details))
            self.bundle_details.configure(state="disabled")
            if approval is not None:
                self.approval = approval
                self.approval_label.configure(text="Для точного пакета найден подписанный допуск к публикации.")
            else:
                self.approval_label.configure(text="Целостность проверена. Подтвердите, что сборка протестирована.")
            self._refresh_receipts()
        self._start("Проверяю готовый пакет", work, complete)

    def _profile(self, *, pin=True):
        old = next(p for p in self.profiles if p.profile_id == self.active_id)
        auth = {"Настроенный ключ этого ПК": "legacy", "Файл SSH-ключа": "key", "Пароль": "password"}[self.auth.get()]
        profile = replace(old, **{key: entry.get().strip() for key, entry in self.fields.items() if key != "port"},
                          port=int(self.fields["port"].get()), auth_method=auth)
        # Retain key bytes only when the operator retained the exact known pin.
        if profile.host_key != old.host_key or profile.host != old.host or profile.port != old.port:
            profile = replace(profile, host_key_data="")
        return validate_profile(profile, require_pin=pin)

    def _credentials(self):
        values = {key: entry.get() for key, entry in self.credential_fields.items()}
        if not values["legacy_key_path"]:
            values["legacy_key_path"] = str(default_keys_path())
        return credentials_from_dict(values)

    def _select_profile_name(self, value):
        profile = next((p for p in self.profiles if self._profile_label(p) == value), None)
        if profile:
            self._select_profile(profile.profile_id)

    @staticmethod
    def _profile_label(profile):
        return profile.name + " [" + profile.profile_id + "]"

    def _select_profile(self, profile_id):
        # An unfinished new profile has never been saved. Discard it when the
        # operator returns to another server, rather than preventing all saves.
        profiles = []
        for profile in self.profiles:
            if profile.profile_id not in {profile_id, "default"}:
                try:
                    validate_profile(profile, require_pin=False)
                except Exception:
                    continue
            profiles.append(profile)
        self.profiles = profiles
        self.active_id = profile_id if any(p.profile_id == profile_id for p in self.profiles) else self.profiles[0].profile_id
        profile = next(p for p in self.profiles if p.profile_id == self.active_id)
        for key, entry in self.fields.items():
            entry.delete(0, "end")
            entry.insert(0, str(getattr(profile, key)))
        self.auth.set({"legacy": "Настроенный ключ этого ПК", "key": "Файл SSH-ключа", "password": "Пароль"}[profile.auth_method])
        credentials = credentials_from_dict(self.saved.get("servers", {}).get(self.active_id))
        for key, entry in self.credential_fields.items():
            entry.delete(0, "end")
            entry.insert(0, getattr(credentials, key))
        self.profile_menu.configure(values=[self._profile_label(p) for p in self.profiles])
        self.profile_menu.set(self._profile_label(profile))
        self._refresh_receipts()

    def _new_profile(self):
        profile = ServerProfile(profile_id="server-" + secrets.token_hex(5), name="Другой сервер " + str(len(self.profiles)),
                                host="", base_url="", host_key="", auth_method="key")
        self.profiles.append(profile)
        self._select_profile(profile.profile_id)

    def _save_settings(self):
        if not self._store_valid:
            self._error("profile_store")
            return
        try:
            profile = self._profile(pin=False)
            profiles = [profile if p.profile_id == profile.profile_id else p for p in self.profiles]
            private = dict(self.saved) if self.remember.get() else {}
            if self.remember.get():
                private["github_token"] = self.token.get()
                private["servers"] = {**private.get("servers", {}), profile.profile_id: credentials_to_dict(self._credentials())}
            self.store.save(profiles, private, profile.profile_id)
            self.profiles, self.saved = profiles, private
            self.profile_menu.configure(values=[self._profile_label(p) for p in profiles])
            self.profile_menu.set(self._profile_label(profile))
            self._log("Настройки издателя сохранены. Адреса у клиентов не менялись.")
        except Exception as error:
            self._error(safe_code(error))

    def _choose_keys(self):
        path = filedialog.askopenfilename(parent=self, title="Файл ключей издателя DPAPI", filetypes=[("JSON", "*.json")])
        if path:
            entry = self.credential_fields["legacy_key_path"]
            entry.delete(0, "end")
            entry.insert(0, path)

    def _probe(self):
        try:
            profile = self._profile(pin=False)
        except Exception as error:
            self._error(safe_code(error))
            return
        def complete(key):
            if messagebox.askyesno("Проверка ключа SSH", "Сверьте этот отпечаток через доверенную консоль VPS:\n\n" + key.fingerprint + "\n\nСохранить его для выбранного сервера?", parent=self):
                known = replace(profile, host_key=key.fingerprint, host_key_type=key.key_type, host_key_data=__import__("base64").b64encode(key.key_data).decode())
                self.profiles = [known if p.profile_id == known.profile_id else p for p in self.profiles]
                self.fields["host_key"].delete(0, "end")
                self.fields["host_key"].insert(0, key.fingerprint)
        from publisher.server import probe_host_key
        self._start("Получаю публичный ключ SSH без входа", lambda emit, cancel: probe_host_key(profile), complete)

    def _approve(self):
        if self.bundle is None or not self.confirmed.get():
            self._error("approval_required")
            return
        try:
            credentials = self._credentials()
        except Exception as error:
            self._error(safe_code(error))
            return
        from publisher.server import approve_local_bundle
        def complete(approval):
            self.approval = approval
            self.approval_label.configure(text="Подписанный допуск сохранён отдельно. Исходный пакет не изменён.")
        self._start("Подтверждаю готовность точного пакета", lambda emit, cancel: approve_local_bundle(self.bundle, credentials), complete)

    def _export(self):
        if not self.bundle:
            self._error("approval_required")
            return
        path = filedialog.asksaveasfilename(parent=self, title="Экспорт готового пакета", defaultextension=".zip",
                                           initialfile=f"TGProxy-{self.bundle.version}-publication.zip", filetypes=[("ZIP", "*.zip")])
        if path:
            self._start("Экспортирую проверенные данные пакета", lambda emit, cancel: export_bundle(self.bundle, self.approval, path), lambda _: self._log("Экспорт готов. Файлы EXE не пересобирались."))

    def _selected(self):
        if not self.bundle:
            from publisher.bundle import BundleError
            raise BundleError("bundle_required")
        profile = self._profile() if self.want_server.get() else None
        credentials = self._credentials()
        return self.bundle, profile, credentials, self.repository.get().strip(), self.token.get().strip(), bool(self.want_github.get())

    def _record(self, bundle, channel, target, report):
        try:
            self.receipts.record(bundle, channel, target, report)
        except Exception:
            report = {**report, "history_error": True}
        return report

    @staticmethod
    def _target(profile):
        return json.dumps([profile.host, profile.port, profile.username, profile.webroot, profile.base_url, profile.host_key])

    def _check_targets(self):
        self._run_channels("Проверяю назначения", "check")

    def _publish(self):
        self._run_channels("Публикую выбранный пакет", "publish")

    def _verify_results(self):
        self._run_channels("Проверяю результаты публикации", "verify")

    def _run_channels(self, label, operation):
        try:
            bundle, profile, credentials, repository, token, github = self._selected()
        except Exception as error:
            self._error(safe_code(error))
            return
        if profile is None and not github:
            self._error("profile")
            return
        approval = self.approval
        cooldown_until = self._github_cooldown_until
        def work(emit, cancel):
            result = {}
            github_precheck = None
            if operation == "publish":
                from publisher.trust import load_approval
                load_approval(bundle, approval)
                # An unavailable channel must not block the other channel, but
                # a conflicting immutable release must be found before writes.
                if github and token and time.monotonic() >= cooldown_until:
                    try:
                        from publisher.github import preflight_github
                        preflight_github(bundle, repository, token, emit=emit, cancel=cancel, allow_missing_tag=True)
                    except Exception as error:
                        github_precheck = error
                        if safe_code(error) in HARD_CONFLICTS:
                            for channel in ((["server"] if profile else []) + ["github"]):
                                report = {"status": "failed", "code": safe_code(error) if channel == "github" else "conflict"}
                                target = repository if channel == "github" else self._target(profile)
                                result[channel] = self._record(bundle, channel, target, report)
                            return result
            blocked = False
            for channel in ("server", "github"):
                if (channel == "server" and profile is None) or (channel == "github" and not github):
                    continue
                if blocked:
                    result[channel] = {"status": "failed", "code": "conflict"}
                    continue
                if cancel.is_set():
                    result[channel] = {"status": "cancelled", "code": "cancelled"}
                    continue
                target = self._target(profile) if channel == "server" else repository
                prepared = None
                try:
                    if channel == "server":
                        from publisher.server import check_server, publish_bundle, verify_publication
                        if operation == "check":
                            report = check_server(profile, credentials, emit=emit, cancel=cancel)
                        elif operation == "verify":
                            report = verify_publication(bundle, profile, emit=emit, cancel=cancel)
                        else:
                            report = publish_bundle(bundle, profile, credentials, emit=emit, cancel=cancel, approval=approval)
                    else:
                        if operation == "publish" and github_precheck is not None:
                            raise github_precheck
                        if time.monotonic() < cooldown_until:
                            from publisher.github import GitHubError
                            raise GitHubError("rate_limited", retry_after=int(cooldown_until - time.monotonic()) + 1)
                        from publisher.github import (preflight_github, prepare_github_draft,
                                                       dispatch_release_workflow, verify_github_publication)
                        if not token:
                            from publisher.profiles import ProfileError
                            raise ProfileError("token")
                        if operation == "check":
                            facts = preflight_github(bundle, repository, token, emit=emit, cancel=cancel, allow_missing_tag=True)
                            report = {"status": "ready", "verified": False}
                        elif operation == "verify":
                            report = verify_github_publication(bundle, repository, token, emit=emit, cancel=cancel)
                        else:
                            prepared = prepare_github_draft(bundle, repository, token, approval=approval, emit=emit, cancel=cancel)
                            self._record(bundle, channel, target, {"status": "draft_ready", "release_url": prepared.get("draft_url", "")})
                            dispatched = dispatch_release_workflow(prepared, repository, token, emit=emit, cancel=cancel)
                            report = {**dispatched, "status": "queued", "verified": False}
                    result[channel] = self._record(bundle, channel, target, report) if operation != "check" else report
                except Exception as error:
                    committed = bool(getattr(error, "committed", False))
                    report = {"status": "verification_pending" if committed else "cancelled" if safe_code(error) == "cancelled" else "failed",
                              "code": safe_code(error), "committed": committed}
                    if safe_code(error) == "publication_unconfirmed":
                        report["status"] = "publication_unconfirmed"
                    if prepared is not None:
                        report.update(status="dispatch_unconfirmed", release_url=prepared.get("draft_url", ""))
                    blocked = safe_code(error) in HARD_CONFLICTS
                    retry = getattr(error, "retry_after", None)
                    if type(retry) in (int, float) and 0 < retry <= 86400:
                        report["retry_after"] = int(retry) + 1
                    if operation != "check":
                        report = self._record(bundle, channel, target, report)
                    result[channel] = report
                emit({"phase": "complete", "channel": channel})
            return result
        self._start(label, work, self._show_results)

    def _show_results(self, result):
        self._last_results.update(result)
        for channel, report in result.items():
            title = "GitHub" if channel == "github" else "Сервер"
            status = STATUSES.get(report.get("status"), "Проверьте результат")
            code = report.get("code")
            retry = report.get("retry_after")
            if channel == "github" and type(retry) in (int, float) and 0 < retry <= 86401:
                self._github_cooldown_until = max(self._github_cooldown_until, time.monotonic() + retry)
            self.channel_labels[channel].configure(text=title + ": " + status + ("\n" + ERRORS.get(code, "Код: " + code) if code else ""))
            self._log(title + ": " + status + (" (" + code + ")" if code else ""))
            if report.get("history_error"):
                self._log(ERRORS["history_store"])
            link = report.get("workflow_url") or report.get("release_url")
            if link:
                self._last_link = link
        self.tabs.set("Публикация")

    def _refresh_receipts(self):
        if not self.bundle:
            return
        try:
            receipts = self.receipts.load()
            profile = self._profile(pin=False)
            for channel, target in (("server", self._target(profile)), ("github", self.repository.get().strip())):
                value = receipts.get(self.receipts.key(self.bundle.bundle_id, channel, target), {})
                title = "GitHub" if channel == "github" else "Сервер"
                self.channel_labels[channel].configure(text=title + ": " + STATUSES.get(value.get("status"), "не проверялось") + " (локальная история)")
        except Exception:
            pass

    def _open_result(self):
        from urllib.parse import urlsplit
        url = self._last_link or "https://github.com/" + self.repository.get().strip() + "/actions/workflows/build.yml"
        parsed = urlsplit(url)
        if parsed.scheme == "https" and parsed.hostname == "github.com" and not parsed.username and not parsed.password:
            webbrowser.open(url)

    def _copy_report(self):
        report = {"publisher": __version__, "version": self.bundle.version if self.bundle else None,
                  "bundle_id": self.bundle.bundle_id if self.bundle else None,
                  "channels": {channel: {k: v for k, v in result.items() if k in {"status", "code", "verified", "public_verified", "committed"}}
                               for channel, result in self._last_results.items()}}
        self.clipboard_clear()
        self.clipboard_append(json.dumps(report, ensure_ascii=False, indent=2))
        self._log("Краткий отчёт скопирован без реквизитов.")

    def _start(self, label, work, complete):
        if self._closing or self.runner.busy:
            return
        self._completion = complete
        if self.runner.start(work):
            self._set_busy(True)
            self.status.configure(text=label)
            self._log(label)

    def _set_busy(self, busy):
        for widget, normal in self._controls:
            widget.configure(state="disabled" if busy else normal)
        self.cancel_button.configure(state="normal" if busy else "disabled")
        if busy:
            self.bar.configure(mode="indeterminate")
            self.bar.start()
            self._animation = True
        elif self._animation:
            self.bar.stop()
            self._animation = False
            self.bar.configure(mode="determinate")
            self.bar.set(0)

    def _poll(self):
        if self.activation_requested.is_set() and not self._closing:
            self.activation_requested.clear()
            self.deiconify()
            self.state("normal")
            self.lift()
            self.focus_force()
        for event in self.runner.poll():
            if self._closing:
                continue
            if event["kind"] == "progress":
                data = event["event"]
                phase = data.get("phase", "")
                label = PHASES.get(phase, "Выполняю операцию")
                if data.get("wait_seconds"):
                    label += f" · ожидание {int(data['wait_seconds'])} с"
                self.status.configure(text=label)
                if phase != self._last_phase:
                    self._last_phase = phase
                    self._log(label)
                total, count = data.get("total"), data.get("bytes", data.get("done"))
                if total and count is not None:
                    self.bar.stop()
                    self._animation = False
                    self.bar.configure(mode="determinate")
                    self.bar.set(min(1, count / total))
                    self.status.configure(text=f"{label} · {int(min(1, count / total) * 100)}% файла")
            else:
                self._set_busy(False)
                if event["kind"] == "error":
                    retry = event.get("retry_after")
                    if type(retry) in (int, float) and 0 < retry <= 86401:
                        self._github_cooldown_until = max(self._github_cooldown_until, time.monotonic() + retry)
                    self._error(event["code"])
                else:
                    try:
                        if self._completion:
                            self._completion(event["value"])
                        self.status.configure(text="Операция завершена. Результат каждого канала показан отдельно.")
                    except Exception as error:
                        self._error(safe_code(error))
                self._completion = None
        if self._closing and self.runner.close():
            self.destroy()
            return
        if not self.runner.busy and time.monotonic() < self._github_cooldown_until:
            remaining = int(self._github_cooldown_until - time.monotonic()) + 1
            self.status.configure(text=f"Ограничение GitHub: ожидание {remaining} с. Сервер можно выбрать отдельно.")
        self.after(60, self._poll)

    def _cancel(self):
        self.runner.request_cancel()
        self.cancel_button.configure(state="disabled")
        self.status.configure(text="Отменяю и ожидаю безопасного завершения. Уже опубликованные файлы сохраняются.")

    def _close(self):
        if self.runner.busy:
            self._closing = True
            self._cancel()
            return
        if self.runner.close():
            self.destroy()

    def _error(self, code):
        message = ERRORS.get(code, "Операция не завершена. Код: " + code)
        self.status.configure(text=message)
        self._log(message)

    def _log(self, text):
        if not hasattr(self, "journal"):
            return
        self.journal.configure(state="normal")
        self.journal.insert("end", text + "\n")
        lines = int(self.journal.index("end-1c").split(".")[0])
        if lines > 500:
            self.journal.delete("1.0", f"{lines - 500}.0")
        self.journal.see("end")
        self.journal.configure(state="disabled")
