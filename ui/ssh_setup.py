"""Inline, explicit SSH installation with a confirmed server-key pin."""
from __future__ import annotations

import logging
import queue
from tkinter import Misc, TclError, messagebox

from ui.background_task import BackgroundTask
from ui.ctk_controls import create_entry, create_label
from ui.i18n import t
from ui.icons import icon_image


log = logging.getLogger("tg-ws-tray")
_STAGES = {
    "connect": "ssh.stage.connect", "verify": "ssh.stage.preflight",
    "upload": "ssh.stage.upload", "install": "ssh.stage.install",
    "verify_result": "ssh.stage.verify",
}


def _probe_server(host, port, username):
    from utils.ssh_setup import SSHOptions, fetch_host_key

    # Probe the transport key without sending credentials to the server.
    return fetch_host_key(SSHOptions(host=host, port=port, username=username, password=""))


def _install_server(host, port, username, password, host_key, progress, *, registry=False,
                    allow_existing_private_upgrade=False):
    from utils.helper_payload import build_helper_payload
    from utils.ssh_setup import SSHOptions, deploy_helper

    options = SSHOptions(host=host, port=port, username=username, password=password)
    if not registry:
        return deploy_helper(options, host_key, build_helper_payload(), progress=progress)
    from proxy.registry_channel import REGISTRY_URL, REGISTRY_PUBLIC_KEY
    from utils.helper_registry import discover_helper
    installed = deploy_helper(options, host_key, build_helper_payload(), progress=progress,
        registry_options={"url": REGISTRY_URL, "public_key": REGISTRY_PUBLIC_KEY,
                          "allow_existing_private_upgrade": allow_existing_private_upgrade is True})
    lease = discover_helper(host, force=True)
    if (lease.port != installed.port or lease.fingerprint != installed.tls_fingerprint
            or lease.helper_id != installed.helper_id):
        raise ValueError("registry_installation_mismatch")
    return lease


class SSHSetup:
    def __init__(self, ctk, parent, theme, *, on_installed, on_busy=None, host_var=None, registry_default=False):
        self.theme, self.on_installed, self.on_busy = theme, on_installed, on_busy
        self.owner = parent.winfo_toplevel()
        self._busy = self._closed = self._expanded = False
        self._phase = None
        self._connection = None
        self._progress_job = None
        self._stages = queue.Queue(maxsize=8)
        self._status_key, self._status_color = None, theme.text_secondary
        self.frame = ctk.CTkFrame(parent, fg_color=theme.surface_alt, corner_radius=12)
        self.header_button = ctk.CTkButton(
            self.frame, text=t("ssh.title"), height=38, corner_radius=10,
            anchor="w", font=(theme.ui_font_family, 12, "bold"),
            fg_color="transparent", hover_color=theme.field_border, text_color=theme.accent,
            image=icon_image("arrow-right", theme, 16, color="accent"), command=self.toggle,
        )
        self.header_button.pack(fill="x", padx=4, pady=4)
        self.details = ctk.CTkFrame(self.frame, fg_color="transparent")
        create_label(
            ctk, self.details, theme, t("ssh.hint"), size=11,
            wraplength=360, justify="left",
        ).pack(fill="x", pady=(0, 12))
        self.host_var = host_var if host_var is not None else ctk.StringVar(master=parent, value="")
        self.port_var = ctk.StringVar(master=parent, value="22")
        self.user_var = ctk.StringVar(master=parent, value="root")
        self.username_var = self.user_var
        self.password_var = ctk.StringVar(master=parent, value="")
        self.registry_var = ctk.BooleanVar(master=parent, value=registry_default)
        self.private_upgrade_var = ctk.BooleanVar(master=parent, value=False)
        self._registry_requested = False
        self._private_upgrade_requested = False
        self._entries = []

        def field(container, key, variable, *, masked=False):
            create_label(ctk, container, theme, t(key), size=11).pack(anchor="w", pady=(0, 4))
            entry = create_entry(
                ctk, container, theme, var=variable, width=1, height=36,
                show="•" if masked else "",
            )
            entry.pack(fill="x")
            self._entries.append(entry)
            return entry

        field(self.details, "ssh.host", self.host_var)
        row = ctk.CTkFrame(self.details, fg_color="transparent")
        row.pack(fill="x", pady=12)
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=2)
        port = ctk.CTkFrame(row, fg_color="transparent")
        port.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        user = ctk.CTkFrame(row, fg_color="transparent")
        user.grid(row=0, column=1, sticky="ew")
        field(port, "ssh.port", self.port_var)
        field(user, "ssh.user", self.user_var)
        self.password_entry = field(self.details, "ssh.password", self.password_var, masked=True)
        create_label(
            ctk, self.details, theme, t("ssh.password_hint"), size=10,
            wraplength=360, justify="left",
        ).pack(fill="x", pady=(5, 12))
        self.registry_switch = ctk.CTkCheckBox(
            self.details, text=t("registry.ssh_access"), variable=self.registry_var,
            font=(theme.ui_font_family, 11), text_color=theme.text_primary,
            fg_color=theme.accent, hover_color=theme.accent_hover)
        self.registry_switch.pack(anchor="w", pady=(0, 6))
        create_label(ctk, self.details, theme, t("registry.ssh_access_hint"), size=10,
                     wraplength=360, justify="left").pack(fill="x", pady=(0, 12))
        self._entries.append(self.registry_switch)
        self.private_upgrade_frame = ctk.CTkFrame(self.details, fg_color="transparent")
        self.private_upgrade_switch = ctk.CTkCheckBox(
            self.private_upgrade_frame, text=t("registry.ssh_private_upgrade"),
            variable=self.private_upgrade_var, font=(theme.ui_font_family, 11),
            text_color=theme.text_primary, fg_color=theme.accent,
            hover_color=theme.accent_hover)
        self.private_upgrade_switch.pack(anchor="w")
        self.private_upgrade_hint = create_label(ctk, self.private_upgrade_frame, theme,
            t("registry.ssh_private_upgrade_hint"), size=10, wraplength=360, justify="left")
        self.private_upgrade_hint.pack(fill="x", pady=(5, 12))
        self._entries.append(self.private_upgrade_switch)
        self.install_button = ctk.CTkButton(
            self.details, text=t("ssh.install"), height=40, corner_radius=10,
            font=(theme.ui_font_family, 12, "bold"), fg_color=theme.accent,
            hover_color=theme.accent_hover, text_color=theme.on_accent,
            command=self.install,
        )
        self.install_button.pack(fill="x")
        self.progress = ctk.CTkProgressBar(
            self.details, mode="indeterminate", height=4, width=1,
            fg_color=theme.field_border, progress_color=theme.accent,
        )
        self.status = create_label(
            ctk, self.details, theme, "", size=11, height=1,
            wraplength=360, justify="left",
        )
        self.status.pack(fill="x", pady=(8, 0))
        self.task = BackgroundTask(self.owner)
        self._consent_traces = []
        for variable in (self.host_var, self.port_var, self.user_var):
            self._consent_traces.append((variable, variable.trace_add("write", self._reset_private_consent)))
        self._consent_traces.append((self.registry_var, self.registry_var.trace_add("write", self._sync_registry)))
        self._sync_registry()
        # CTkFrame.bind targets its canvas; bind the frame's own lifecycle.
        Misc.bind(self.frame, "<Destroy>", self._destroy, add="+")

    def _reset_private_consent(self, *_):
        self.private_upgrade_var.set(False)

    def _sync_registry(self, *_):
        if self.registry_var.get():
            self.private_upgrade_frame.pack(fill="x", before=self.install_button)
        else:
            self.private_upgrade_frame.pack_forget()
            self._reset_private_consent()

    @property
    def busy(self):
        return self._busy

    def toggle(self):
        if self._closed or self.busy:
            return
        self._expanded = not self._expanded
        if self._expanded:
            self.details.pack(fill="x", padx=14, pady=(8, 14))
        else:
            self.details.pack_forget()
        self.header_button.configure(image=icon_image(
            "arrow-down" if self._expanded else "arrow-right", self.theme, 16, color="accent",
        ))

    def refresh(self):
        if self._closed:
            return
        self.header_button.configure(text=t("ssh.title"))
        self.install_button.configure(text=t("ssh.install"))
        if self._status_key:
            self.status.configure(text=t(self._status_key), text_color=self._status_color)

    def _status(self, key, color=None):
        self._status_key = key
        self._status_color = color or self.theme.text_secondary
        self.refresh()

    def _notify_busy(self, value):
        if self.on_busy is not None:
            try:
                self.on_busy(value)
            except TclError:
                pass  # A containing dialog may be being destroyed.
            except Exception as exc:
                log.warning("SSH setup busy callback failed (%s)", type(exc).__name__)

    def _set_busy(self, value):
        self._busy = value
        for widget in (self.header_button, self.install_button, *self._entries):
            widget.configure(state="disabled" if value else "normal")
        if value:
            self.progress.pack(fill="x", pady=(10, 0), after=self.install_button)
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.pack_forget()
        self._notify_busy(value)

    def _clear_password(self):
        try:
            self.password_var.set("")
        except TclError:
            pass

    def _cancel_progress(self):
        if self._progress_job is not None:
            try:
                self.owner.after_cancel(self._progress_job)
            except TclError:
                pass
            self._progress_job = None

    def _finish(self, key, color=None):
        self._clear_password()
        self._reset_private_consent()
        self._phase, self._connection = None, None
        self._cancel_progress()
        if not self._closed:
            self._set_busy(False)
            self._status(key, color)

    def _failure(self, kind):
        # Exception messages and remote output may contain supplied secrets.
        log.warning("SSH helper setup failed (%s)", kind)
        self._finish("ssh.error", self.theme.danger)

    def _progress(self, stage):
        if stage in _STAGES:
            try:
                self._stages.put_nowait(stage)
            except queue.Full:
                pass

    def _poll_progress(self):
        self._progress_job = None
        if self._closed or not self.busy:
            return
        while True:
            try:
                self._status_key = _STAGES[self._stages.get_nowait()]
            except queue.Empty:
                break
        self.refresh()
        self._progress_job = self.owner.after(100, self._poll_progress)

    def install(self):
        if self._closed or self.busy:
            return
        host, user = self.host_var.get().strip(), self.user_var.get().strip()
        if not host:
            self._status("ssh.invalid_host", self.theme.danger)
            return
        try:
            port = int(self.port_var.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self._status("validation.bad_port", self.theme.danger)
            return
        if not user or not self.password_var.get():
            self._status("ssh.credentials_required", self.theme.danger)
            return
        self._connection = (host, port, user)
        self._registry_requested = bool(self.registry_var.get())
        self._private_upgrade_requested = bool(self.private_upgrade_var.get())
        self._phase = "probe"
        self._set_busy(True)
        self._status("ssh.checking")
        while not self._stages.empty():
            self._stages.get_nowait()
        self._poll_progress()

        def work():
            try:
                return True, _probe_server(host, port, user)
            except Exception as exc:
                return False, type(exc).__name__

        def complete(outcome):
            if self._closed:
                return
            success, identity = outcome
            if not success:
                self._failure(identity)
                return
            try:
                accepted = messagebox.askyesno(
                    t("ssh.host_key_title"), t("ssh.host_key_prompt", host=host, port=port,
                                               algorithm=identity.key_type,
                                               fingerprint=identity.fingerprint),
                    parent=self.owner, default="no", icon="warning",
                )
            except Exception as exc:
                self._failure(type(exc).__name__)
                return
            if self._closed:
                return
            if not accepted:
                self._finish("ssh.cancelled", self.theme.text_muted)
                return
            self._begin_deploy(identity)

        def finish():
            # The completion callback starts phase two on the same task. Do
            # not reset its busy state when phase one's poll finally returns.
            if not self._closed and self._phase == "probe":
                self._failure("BackgroundTask")

        self.task.start(work, complete, finish)

    def _begin_deploy(self, identity):
        host, port, user = self._connection
        password = self.password_var.get()
        registered = self._registry_requested
        private_upgrade = self._private_upgrade_requested
        self._phase = "deploy"
        self._status("ssh.stage.connect")

        def work():
            nonlocal password
            try:
                result = (_install_server(host, port, user, password, identity, self._progress,
                                          registry=True, allow_existing_private_upgrade=private_upgrade)
                          if registered else _install_server(host, port, user, password, identity, self._progress))
                return True, result
            except Exception as exc:
                return False, type(exc).__name__
            finally:
                password = ""

        def complete(outcome):
            if self._closed:
                return
            success, result = outcome
            self._clear_password()
            if not success:
                self._failure(result)
                return
            try:
                self.on_installed(result)
            except Exception as exc:
                self._failure(type(exc).__name__)
                return
            self._finish("ssh.installed", self.theme.success)

        def finish():
            if not self._closed and self._phase == "deploy":
                self._failure("BackgroundTask")

        self.task.start(work, complete, finish)

    def _destroy(self, event):
        if event.widget is not self.frame:
            return
        was_busy = self.busy
        self._closed, self._busy = True, False
        for variable, trace in self._consent_traces:
            try:
                variable.trace_remove("write", trace)
            except TclError:
                pass
        self._connection = self._phase = None
        # CTkEntry 5.2 leaves its textvariable trace attached after destroying
        # the native Entry. Remove that owned trace before erasing the secret,
        # otherwise the write callback queries a widget that no longer exists.
        trace = getattr(self.password_entry, "_textvariable_callback_name", "")
        if trace:
            try:
                self.password_var.trace_remove("write", trace)
            except TclError:
                pass
            self.password_entry._textvariable_callback_name = ""
        self._clear_password()
        self._cancel_progress()
        self.task.closed = True
        if self.task.pending is not None:
            try:
                self.owner.after_cancel(self.task.pending)
            except TclError:
                pass
            self.task.pending = None
        try:
            self.progress.stop()
        except TclError:
            pass
        if was_busy:
            self._notify_busy(False)
