import unittest
import threading
from unittest.mock import Mock, patch
from proxy import config as config_module

from proxy.config import (
    CFPROXY_DEFAULT_DOMAINS,
    _is_valid_domain,
    _normalize_domain_pool,
    coerce_domain_list,
    parse_dc_ip_list,
)


class ParseDcIpListTest(unittest.TestCase):
    def test_parses_multiple_entries(self):
        self.assertEqual(
            parse_dc_ip_list(['2:149.154.167.220', '4:149.154.167.91']),
            {2: '149.154.167.220', 4: '149.154.167.91'},
        )

    def test_last_entry_wins_for_duplicate_dc(self):
        self.assertEqual(parse_dc_ip_list(['2:149.154.167.220', '2:149.154.167.51']), {2: '149.154.167.51'})

    def test_rejects_missing_separator(self):
        with self.assertRaises(ValueError) as ctx:
            parse_dc_ip_list(['2-1.2.3.4'])
        self.assertEqual(ctx.exception.kind, 'format')

    def test_rejects_short_form_ipv4(self):
        for entry in ('2:149.154', '2:1.2.3.4.5', '2:999.1.1.1', '2:abc'):
            with self.subTest(entry=entry), self.assertRaises(ValueError) as ctx:
                parse_dc_ip_list([entry])
            self.assertEqual(ctx.exception.kind, 'invalid')

    def test_rejects_non_numeric_dc(self):
        with self.assertRaises(ValueError):
            parse_dc_ip_list(['x:1.2.3.4'])


class CoerceDomainListTest(unittest.TestCase):
    def test_splits_on_common_separators(self):
        self.assertEqual(
            coerce_domain_list('a.com, b.com; c.com d.com'),
            ['a.com', 'b.com', 'c.com', 'd.com'],
        )

    def test_deduplicates_case_insensitively_keeping_first(self):
        self.assertEqual(coerce_domain_list(['A.com', 'a.com']), ['A.com'])

    def test_flattens_sequences_and_skips_non_strings(self):
        self.assertEqual(coerce_domain_list(['a.com b.com', 5, None]), ['a.com', 'b.com'])

    def test_returns_empty_for_unsupported_types(self):
        self.assertEqual(coerce_domain_list(None), [])
        self.assertEqual(coerce_domain_list(42), [])


class DomainValidationTest(unittest.TestCase):
    def test_accepts_ordinary_domains(self):
        for domain in ('example.com', 'a-b.co.uk', 'x.io'):
            self.assertTrue(_is_valid_domain(domain), domain)

    def test_rejects_malformed_domains(self):
        for domain in ('', 'nodot', '.leading.com', 'trailing.com.',
                       '-bad.com', 'bad-.com', 'a..com', 'a.1',
                       'a.' + 'b' * 64, 'a' * 250 + '.com'):
            self.assertFalse(_is_valid_domain(domain), domain)

    def test_normalize_lowercases_dedupes_and_drops_invalid(self):
        self.assertEqual(
            _normalize_domain_pool(['B.com ', 'b.com', 'nodot', 'a.com']),
            ['b.com', 'a.com'],
        )


class DefaultDomainsTest(unittest.TestCase):
    def test_decoded_defaults_are_valid_domains(self):
        self.assertTrue(CFPROXY_DEFAULT_DOMAINS)
        for domain in CFPROXY_DEFAULT_DOMAINS:
            self.assertTrue(_is_valid_domain(domain), domain)

    def test_decoded_defaults_are_unique(self):
        self.assertEqual(
            len(set(CFPROXY_DEFAULT_DOMAINS)), len(CFPROXY_DEFAULT_DOMAINS)
        )


class DomainRefreshLifecycleTest(unittest.TestCase):
    def test_redirect_is_https_only_and_does_not_drain_body(self):
        from urllib.request import Request, HTTPRedirectHandler
        handler = config_module._DomainListRedirect()
        request = Request('https://example.org/domains')
        for url in ('http://example.org/list', 'file:///config', 'https://user:password@example.org/list'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, '', {}, url)
        redirected = handler.redirect_request(request, None, 302, '', {}, 'https://example.org/list')
        self.assertEqual(redirected.full_url, 'https://example.org/list')
        response = Mock()

        def next_handler(*args):
            response.close.assert_called_once()
            response.read.assert_not_called()
            return 'redirected'

        with patch.object(HTTPRedirectHandler, 'http_error_302', side_effect=next_handler):
            self.assertEqual(handler.http_error_302(request, response, 302, '', {}), 'redirected')

    def test_http_error_response_is_closed_and_only_safe_type_is_logged(self):
        from urllib.error import HTTPError
        body = Mock()
        error = HTTPError('https://example.org/synthetic-secret', 503, 'synthetic-secret', {}, body)
        opener = Mock()
        opener.open.side_effect = error
        with patch.object(config_module, 'build_github_opener', return_value=opener), \
                self.assertLogs(config_module.log, level='WARNING') as captured:
            self.assertEqual(config_module._fetch_cfproxy_domain_list(), [])
        body.close.assert_called_once()
        self.assertNotIn('synthetic-secret', ' '.join(captured.output))

    def test_response_read_is_bounded_and_oversize_is_rejected(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'x' * (config_module._CFPROXY_MAX_RESPONSE_BYTES + 1)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(config_module, 'build_github_opener', return_value=opener):
            self.assertEqual(config_module._fetch_cfproxy_domain_list(), [])
        response.read.assert_called_once_with(config_module._CFPROXY_MAX_RESPONSE_BYTES + 1)
        response.__exit__.assert_called_once()

    def test_too_many_small_remote_domains_are_rejected(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'example.net\n' * (config_module._CFPROXY_MAX_DOMAINS + 1)
        opener = Mock()
        opener.open.return_value = response
        with patch.object(config_module, 'build_github_opener', return_value=opener):
            self.assertEqual(config_module._fetch_cfproxy_domain_list(), [])

    def test_late_response_cannot_overwrite_manual_routes_or_stopped_generation(self):
        for manual in (False, True):
            with self.subTest(manual=manual):
                stop = threading.Event()
                runtime = config_module.ProxyConfig()

                def fetch():
                    if manual:
                        runtime.cfproxy_user_domains = ['manual.example']
                    else:
                        stop.set()
                    return ['a.example', 'b.example', 'c.example']

                with patch.object(config_module, 'proxy_config', runtime), \
                        patch.object(config_module, '_fetch_cfproxy_domain_list', side_effect=fetch), \
                        patch.object(config_module.balancer, 'update_domains_list') as update:
                    config_module.refresh_cfproxy_domains(stop)
                update.assert_not_called()

    def test_only_one_fetch_can_be_in_flight_across_generations(self):
        entered, release = threading.Event(), threading.Event()
        stop = threading.Event()
        runtime = config_module.ProxyConfig()

        def fetch():
            entered.set()
            self.assertTrue(release.wait(2))
            return ['a.example', 'b.example', 'c.example']

        with patch.object(config_module, 'proxy_config', runtime), \
                patch.object(config_module, '_fetch_cfproxy_domain_list', side_effect=fetch) as fetching, \
                patch.object(config_module.balancer, 'update_domains_list') as update:
            worker = threading.Thread(target=config_module.refresh_cfproxy_domains, args=(stop,))
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                stop.set()
                self.assertFalse(config_module.refresh_cfproxy_domains(threading.Event()))
                self.assertEqual(fetching.call_count, 1)
            finally:
                release.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
            update.assert_not_called()

    def test_worker_start_failure_keeps_defaults_without_crashing_proxy(self):
        with patch.object(config_module.threading, 'Thread') as thread, \
                patch.object(config_module.balancer, 'update_domains_list') as update:
            thread.return_value.start.side_effect = RuntimeError('synthetic thread limit')
            config_module.start_cfproxy_domain_refresh()
            self.assertTrue(config_module._refresh_stop.is_set())
            update.assert_called_once_with(CFPROXY_DEFAULT_DOMAINS)


if __name__ == '__main__':
    unittest.main()
