from __future__ import annotations

from tkinter import messagebox
from typing import Any

from proxy.utils import DC_DEFAULT_IPS
from proxy.config import coerce_domain_list
from utils.route_diagnostics import MAX_DOMAINS, RouteCase, run_route_checks
from ui.i18n import t

_CFPROXY_TEST_DCS = [1, 2, 3, 4, 5, 203]
_CFWORKER_TEST_DST = DC_DEFAULT_IPS


class ConnectivityResults(dict):
    """Compatible mapping with explicit limits and completeness metadata."""
    def __init__(self, *args, tested=0, total=0, incomplete=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.tested, self.total, self.incomplete = tested, total, incomplete


def _display_result(result):
    return True if result.status == 'ok' else t('connectivity.error_' + result.error_code)


def _run_connectivity_test(cases: list, *, secure: bool = True, cancel=None) -> dict:
    probes = [RouteCase(0, dc, host, sni, domain, path)
              for dc, host, sni, domain, path in cases]
    results = run_route_checks(probes, secure=secure, cancel=cancel)
    return ConnectivityResults({v.dc: _display_result(v) for v in results},
        tested=1, total=1, incomplete=any(v.status in ('cancelled', 'incomplete') for v in results))


def _run_cfproxy_connectivity_test(domain: str, *, secure: bool = True, cancel=None) -> dict:
    cases = []
    for dc in _CFPROXY_TEST_DCS:
        host = f"kws{dc}.{domain}"
        cases.append((dc, host, host, host, "/apiws"))
    return _run_connectivity_test(cases, secure=secure, cancel=cancel)


def _run_cfworker_connectivity_test(domain: str, *, secure: bool = True, cancel=None) -> dict:
    cases = []
    for dc in _CFPROXY_TEST_DCS:
        dst = _CFWORKER_TEST_DST[dc]
        path = f"/apiws?dst={dst}&dc={dc}&media=0"
        cases.append((dc, domain, domain, domain, path))
    return _run_connectivity_test(cases, secure=secure, cancel=cancel)


def _multi_test(domains, *, worker, secure, cancel):
    domains = coerce_domain_list(domains)
    selected = domains[:MAX_DOMAINS]
    probes = []
    for index, domain in enumerate(selected):
        for dc in _CFPROXY_TEST_DCS:
            host = domain if worker else f'kws{dc}.{domain}'
            path = f'/apiws?dst={_CFWORKER_TEST_DST[dc]}&dc={dc}' if worker else '/apiws'
            probes.append(RouteCase(index, dc, host, host, host, path))
    values = run_route_checks(probes, secure=secure, cancel=cancel)
    per = ConnectivityResults({d: {} for d in selected}, tested=len(selected), total=len(domains),
        incomplete=any(v.status in ('cancelled', 'incomplete') for v in values))
    for value in values:
        per[selected[value.candidate]][value.dc] = _display_result(value)
    return per


def run_cfproxy_multi_test(domains: list, *, secure: bool = True, cancel=None) -> dict:
    return _multi_test(domains, worker=False, secure=secure, cancel=cancel)


def run_cfworker_multi_test(domains: list, *, secure: bool = True, cancel=None) -> dict:
    return _multi_test(domains, worker=True, secure=secure, cancel=cancel)


def run_cfproxy_auto_test(domains: list, *, secure: bool = True, cancel=None) -> tuple:
    per = run_cfproxy_multi_test(list(reversed(domains)), secure=secure, cancel=cancel)
    merged = ConnectivityResults(tested=per.tested, total=per.total, incomplete=per.incomplete)
    best_domain = None
    for domain, res in per.items():
        if all(v is True for v in res.values()):
            merged.update(res)
            return domain, merged
        for dc, v in res.items():
            if v is True:
                merged[dc] = True
                best_domain = domain
            elif dc not in merged:
                merged[dc] = v
    return best_domain, merged


def _scope_note(results):
    note = '\n\n' + t('connectivity.transport_only')
    tested, total = getattr(results, 'tested', 0), getattr(results, 'total', 0)
    if total > tested:
        note += '\n' + t('connectivity.coverage', tested=tested, total=total)
    if getattr(results, 'incomplete', False):
        note += '\n' + t('connectivity.incomplete')
    return note


def show_connectivity_results(title_base: str, results: dict,
                               domain: str = '', label_prefix: str = 'DC',
                               auto_mode: bool = False,
                               unavailable_message: str = '', *, parent: Any) -> None:
    ok = [dc for dc, v in results.items() if v is True]
    total = len(_CFPROXY_TEST_DCS)
    if auto_mode:
        if domain:
            title = t("connectivity.available", title=title_base)
            msg = t("connectivity.auto_ok", title=title_base, ok=len(ok), total=total)
        else:
            title = t("connectivity.unavailable", title=title_base)
            msg = unavailable_message
    else:
        fail = [(dc, v) for dc, v in results.items() if v is not True]
        if len(ok) == total:
            title = t("connectivity.all_ok", title=title_base)
            msg = t("connectivity.all_ok_domain", total=total, domain=domain)
        elif not ok:
            title = t("connectivity.unavailable", title=title_base)
            errors = "\n".join(
                t("connectivity.error_line", prefix=label_prefix, dc=dc, error=v)
                for dc, v in fail
            )
            msg = t("connectivity.none_ok", domain=domain, errors=errors)
        else:
            title = t("connectivity.partial", title=title_base)
            ok_list = ", ".join(f"{label_prefix}{dc}" for dc in ok)
            fail_list = "\n".join(
                t("connectivity.error_line", prefix=label_prefix, dc=dc, error=v)
                for dc, v in fail
            )
            msg = t("connectivity.partial_detail", domain=domain, ok_list=ok_list, fail_list=fail_list)

    messagebox.showinfo(title, msg + _scope_note(results), parent=parent)


def show_multi_connectivity_results(title_base: str, per_domain: dict,
                                     label_prefix: str = 'DC', *, parent: Any) -> None:
    total = len(_CFPROXY_TEST_DCS)
    all_ok = bool(per_domain) and not getattr(per_domain, 'incomplete', False)
    any_ok = False
    blocks = []
    for domain, results in per_domain.items():
        ok = [dc for dc, v in results.items() if v is True]
        fail = [(dc, v) for dc, v in results.items() if v is not True]
        if len(ok) == total:
            any_ok = True
            blocks.append(t("connectivity.multi_all_ok", domain=domain, total=total))
        elif not ok:
            all_ok = False
            blocks.append(t("connectivity.multi_fail", domain=domain))
        else:
            all_ok = False
            any_ok = True
            ok_list = ", ".join(f"{label_prefix}{dc}" for dc in ok)
            fail_list = ", ".join(f"{label_prefix}{dc}" for dc, _ in fail)
            blocks.append(
                t("connectivity.multi_partial", domain=domain, ok_list=ok_list, fail_list=fail_list)
            )

    if all_ok:
        title = t("connectivity.all_ok", title=title_base)
    elif any_ok:
        title = t("connectivity.partial", title=title_base)
    else:
        title = t("connectivity.unavailable", title=title_base)
    msg = "\n\n".join(blocks)

    messagebox.showinfo(title, msg + _scope_note(per_domain), parent=parent)
