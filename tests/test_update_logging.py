"""Update checks stay observable at INFO without disclosing remote error text."""
import io
import logging
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from proxy.config import ProxyConfig
from utils import tray_common, update_check
from utils.live_logs import LiveLogHandler


ASSET_NAME = 'TgWsProxy_windows.exe'
DIGEST = 'sha256:' + 'a' * 64


def github(version='1.14.5', *, installable=True):
    return {
        'tag_name': 'v' + version,
        'html_url': 'https://github.com/example/project/releases/' + version,
        'body': 'do-not-log-release-notes',
        'assets': [{
            'name': ASSET_NAME,
            'browser_download_url': 'https://downloads.invalid/application.exe?token=do-not-log-url-token',
            'digest': DIGEST if installable else '',
        }],
    }


def backup(version='1.14.5'):
    return {
        'latest': version, 'source': 'backup', 'html_url': 'https://updates.invalid/releases',
        'notes': 'do-not-log-signed-notes',
        'assets': [{
            'name': ASSET_NAME,
            'url': 'https://updates.invalid/application.exe?token=do-not-log-backup-token',
            'digest': DIGEST,
        }],
    }


class UpdateCheckLoggingTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(update_check, '_state', update_check.get_status()))
        self.stack.enter_context(patch.object(update_check, '_compatible_asset_names', return_value={ASSET_NAME}))
        self.stack.enter_context(patch.object(update_check, 'UPDATE_MANIFEST_URL', 'https://updates.invalid/latest.json'))
        self.primary = self.stack.enter_context(patch.object(update_check, 'fetch_latest_release'))
        self.reserve = self.stack.enter_context(patch.object(update_check, 'fetch_backup_release'))

    def check(self, current='1.14.4', **kwargs):
        with self.assertLogs('tg-updater', level=logging.INFO) as captured:
            update_check.run_check(current, **kwargs)
        self.records = captured.records
        self.messages = [record.getMessage() for record in self.records]
        self.assertTrue(all(record.name == 'tg-updater' for record in self.records))
        outcomes = [record for record in self.records
                    if record.getMessage().startswith('Проверка обновлений завершена:')]
        self.assertEqual(len(outcomes), 1)
        self.outcome = outcomes[0]
        return '\n'.join(self.messages)

    def test_github_update_is_visible_at_info_without_contacting_backup(self):
        self.primary.return_value = github()
        output = self.check()
        self.reserve.assert_not_called()
        self.assertEqual([record.levelno for record in self.records], [logging.INFO] * 4)
        self.assertIn('текущая версия 1.14.4', self.messages[0])
        self.assertIn('обращаемся к GitHub', self.messages[1])
        self.assertIn('GitHub: опубликована версия 1.14.5', self.messages[2])
        self.assertIn('доступна версия 1.14.5', self.outcome.getMessage())
        self.assertIn('источник: GitHub', self.outcome.getMessage())
        self.assertTrue(update_check.get_status()['has_update'])
        for hidden in ('do-not-log-release-notes', 'do-not-log-url-token', 'https://', ASSET_NAME):
            self.assertNotIn(hidden, output)

    def test_missing_public_release_is_not_reported_as_connection_failure(self):
        self.primary.side_effect = HTTPError(
            'https://user:do-not-log-password@private.invalid/path?token=do-not-log-error-token',
            404, 'do-not-log-http-reason', {'X-Secret': 'do-not-log-header'}, None)
        self.reserve.return_value = backup('1.14.4')
        output = self.check()
        self.assertFalse(any(record.levelno >= logging.WARNING for record in self.records))
        self.assertIn('GitHub ответил HTTP 404', output)
        self.assertIn('резервному серверу — публичный стабильный релиз GitHub недоступен', output)
        self.assertNotIn('Проверка GitHub не удалась', output)
        self.assertIn('подпись манифеста проверена; версия 1.14.4', output)
        self.assertEqual(self.outcome.levelno, logging.INFO)
        self.assertIn('обновлений не найдено', self.outcome.getMessage())
        self.assertIn('источник: резервный сервер', self.outcome.getMessage())
        self.assertEqual(update_check.get_status()['source'], 'backup')
        for hidden in ('do-not-log-password', 'do-not-log-error-token', 'do-not-log-http-reason',
                       'do-not-log-header', 'do-not-log-signed-notes', 'do-not-log-backup-token', 'https://'):
            self.assertNotIn(hidden, output)

    def test_no_public_release_without_backup_is_neutral_not_up_to_date(self):
        self.primary.side_effect = HTTPError('https://secret.invalid', 404, 'secret', {}, None)
        output = self.check(server_url='')
        self.reserve.assert_not_called()
        state = update_check.get_status()
        self.assertIsNone(state['error'])
        self.assertIsNone(state['latest'])
        self.assertEqual(state['http_status'], 404)
        self.assertEqual(state['github_result'], 'no_public_release')
        self.assertFalse(state['has_update'])
        self.assertFalse(state['ahead_of_release'])
        self.assertNotIn('обновлений не найдено', output)
        self.assertFalse(any(record.levelno >= logging.WARNING for record in self.records))

    def test_permissions_and_rate_limits_remain_real_failures(self):
        for code in (401, 403, 429, 500):
            with self.subTest(code=code):
                self.primary.side_effect = HTTPError('https://secret.invalid', code, 'secret', {}, None)
                output = self.check(server_url='')
                self.assertIn('Проверка GitHub не удалась (HTTP ' + str(code) + ')', output)
                self.assertEqual(update_check.get_status()['github_result'], 'check_failed')
                self.assertTrue(update_check.get_status()['error'])
                self.assertNotIn('no_public_release', output)

    def test_no_newer_github_release_explains_why_backup_is_checked(self):
        self.primary.return_value = github('1.14.4')
        self.reserve.return_value = backup('1.14.5')
        output = self.check()
        self.assertIn('на GitHub нет более новой версии для этого клиента', output)
        self.assertIn('доступна версия 1.14.5', self.outcome.getMessage())
        self.assertIn('источник: резервный сервер', self.outcome.getMessage())

    def test_missing_verified_installer_explains_same_version_server_fallback(self):
        self.primary.return_value = github(installable=False)
        self.reserve.return_value = backup()
        output = self.check()
        self.assertIn('на GitHub нет подходящего проверяемого файла установки', output)
        self.assertEqual(update_check.get_status()['source'], 'backup')
        self.assertIn('источник: резервный сервер', self.outcome.getMessage())

    def test_newer_local_build_is_distinct_from_up_to_date(self):
        self.primary.return_value = github('1.14.3')
        self.reserve.return_value = backup('1.14.4')
        self.check('1.14.5')
        self.assertIn('установленная версия 1.14.5 новее опубликованной 1.14.4', self.outcome.getMessage())
        self.assertTrue(update_check.get_status()['ahead_of_release'])

    def test_failed_backup_keeps_successful_github_result_at_info(self):
        self.primary.return_value = github('1.14.4')
        self.reserve.side_effect = ValueError('do-not-log-untrusted-manifest-details')
        output = self.check()
        self.assertIn('Проверка резервного сервера не удалась (данные отклонены при проверке)', output)
        self.assertEqual(self.outcome.levelno, logging.INFO)
        self.assertIn('источник: GitHub', self.outcome.getMessage())
        self.assertIsNone(update_check.get_status()['error'])
        self.assertNotIn('do-not-log-untrusted-manifest-details', output)
        self.assertFalse(any(record.levelno >= logging.ERROR for record in self.records))

    def test_both_channels_failed_have_warnings_and_one_final_error(self):
        self.primary.side_effect = URLError('do-not-log-network-token')
        self.reserve.side_effect = TimeoutError('do-not-log-timeout-secret')
        output = self.check()
        warnings = [record for record in self.records if record.levelno == logging.WARNING]
        self.assertEqual(len(warnings), 2)
        self.assertIn('ошибка сети', warnings[0].getMessage())
        self.assertIn('истекло время ожидания', warnings[1].getMessage())
        self.assertEqual(self.outcome.levelno, logging.ERROR)
        self.assertIn('не удалось получить сведения об обновлениях', self.outcome.getMessage())
        self.assertEqual(len([r for r in self.records if r.levelno == logging.ERROR]), 1)
        self.assertTrue(update_check.get_status()['error'])
        self.assertNotIn('do-not-log-network-token', output)
        self.assertNotIn('do-not-log-timeout-secret', output)

    def test_disabled_backup_does_not_claim_that_another_source_was_checked(self):
        self.primary.side_effect = HTTPError('https://secret.invalid', 403, 'secret', {}, None)
        output = self.check(server_url='')
        self.reserve.assert_not_called()
        self.assertNotIn('обращаемся к резервному серверу', output)
        self.assertEqual(self.outcome.levelno, logging.ERROR)

    def test_malformed_version_and_current_input_cannot_inject_log_lines(self):
        self.primary.return_value = github('1.14.5\ndo-not-log-remote-injection')
        self.reserve.return_value = backup()
        output = self.check('do-not-log-current-secret\nERROR forged event')
        self.assertIn('текущая версия неизвестна', output)
        self.assertIn('данные отклонены при проверке', output)
        self.assertNotIn('do-not-log-remote-injection', output)
        self.assertNotIn('do-not-log-current-secret', output)
        self.assertNotIn('forged event', output)


class ManagedUpdateLogsTest(unittest.TestCase):
    def test_nonverbose_file_console_and_dashboard_receive_one_check_result(self):
        root = logging.getLogger()
        old_handlers, old_level = root.handlers[:], root.level
        updater = logging.getLogger('tg-updater')
        old_updater = updater.level, updater.propagate, updater.disabled
        old_asyncio = logging.getLogger('asyncio').level
        root.handlers = []
        updater.setLevel(logging.NOTSET)
        updater.propagate, updater.disabled = True, False
        with tempfile.TemporaryDirectory() as folder:
            log_path = Path(folder) / 'proxy.log'
            console = io.StringIO()
            history = LiveLogHandler()
            try:
                with ExitStack() as stack:
                    for key, value in (
                        ('ensure_dirs', Mock()), ('LOG_FILE', log_path), ('live_logs', history),
                        ('IS_FROZEN', False), ('proxy_config', ProxyConfig()),
                    ):
                        stack.enter_context(patch.object(tray_common, key, value))
                    stack.enter_context(patch('sys.stdout', console))
                    stack.enter_context(patch.object(update_check, '_state', update_check.get_status()))
                    stack.enter_context(patch.object(update_check, '_compatible_asset_names', return_value={ASSET_NAME}))
                    stack.enter_context(patch.object(update_check, 'fetch_latest_release', return_value=github()))
                    stack.enter_context(patch.object(update_check, 'fetch_backup_release'))
                    tray_common.setup_logging(verbose=False)
                    update_check.run_check('1.14.4')
                    updater.debug('hidden-debug-update-detail')
                    for handler in root.handlers:
                        handler.flush()
                    outputs = (log_path.read_text(encoding='utf-8'),
                               '\n'.join(history.read_since()[1]), console.getvalue())
                    for output in outputs:
                        self.assertIn('INFO', output)
                        self.assertIn('Проверка обновлений: текущая версия 1.14.4', output)
                        self.assertIn('доступна версия 1.14.5', output)
                        self.assertEqual(output.count('Проверка обновлений завершена:'), 1)
                        self.assertNotIn('hidden-debug-update-detail', output)
                        self.assertNotIn('do-not-log-url-token', output)
                    self.assertTrue(any(entry.name == 'tg-updater' for entry in history.read_entries_since()[1]))
            finally:
                for handler in root.handlers[:]:
                    root.removeHandler(handler)
                    handler.close()
                root.handlers = old_handlers
                root.setLevel(old_level)
                updater.setLevel(old_updater[0])
                updater.propagate, updater.disabled = old_updater[1:]
                logging.getLogger('asyncio').setLevel(old_asyncio)


if __name__ == '__main__':
    unittest.main()
