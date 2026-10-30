"""Exercise tray lifecycle on isolated workers and real loopback listeners."""
import asyncio
import socket
import threading
import time
import unittest
import weakref
from contextlib import ExitStack
from unittest.mock import AsyncMock, Mock, patch

from proxy import tg_ws_proxy
from proxy.config import ProxyConfig
from utils import tray_common
from utils.default_config import default_tray_config


class ProxyLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.workers, self.controls, self.gates = [], [], []
        self.original_thread = threading.Thread
        self.runtime = ProxyConfig()
        self.config = default_tray_config()
        self.config.update(host="127.0.0.1", port=0, dc_ip=[], pool_size=0,
                           cfproxy=False, h2=False, secret="a" * 32)
        for name, value in (("_proxy_thread", None), ("_async_stop", None),
                            ("_proxy_stop_requested", None), ("PROXY_STOP_TIMEOUT", 0.05)):
            self.stack.enter_context(patch.object(tray_common, name, value, create=True))
        self.stack.enter_context(patch.object(tray_common, "proxy_config", self.runtime))
        self.stack.enter_context(patch.object(tg_ws_proxy, "proxy_config", self.runtime))
        self.stack.enter_context(patch.object(tg_ws_proxy, "start_cfproxy_domain_refresh"))
        self.stack.enter_context(patch.object(tg_ws_proxy.ws_pool, "warmup", AsyncMock()))
        self.stack.enter_context(patch.object(tg_ws_proxy.cf_worker_pool, "warmup", AsyncMock()))
        self.stack.enter_context(patch.object(tray_common.threading, "Thread", side_effect=self.make_thread))
        self.error = Mock()

    def make_thread(self, *args, **kwargs):
        worker = self.original_thread(*args, **kwargs)
        if kwargs.get("name") == "proxy":
            self.workers.append(worker)
        return worker

    def tearDown(self):
        for gate in self.gates:
            gate.set()
        request = getattr(tray_common, "_proxy_stop_requested", None)
        if request is not None:
            request.set()
        for loop, event in self.controls:
            try:
                loop.call_soon_threadsafe(event.set)
            except RuntimeError:
                pass
        for worker in self.workers:
            worker.join(timeout=2)
        alive = [worker.name for worker in self.workers if worker.is_alive()]
        self.stack.close()
        self.assertFalse(alive, f"Leaked proxy workers: {alive}")

    def install_run(self, body=None):
        started = threading.Event()

        async def run(stop_event):
            self.controls.append((asyncio.get_running_loop(), stop_event))
            started.set()
            if body is None:
                await asyncio.wait_for(stop_event.wait(), 1)
            else:
                await body(stop_event)

        self.stack.enter_context(patch.object(tray_common, "_run", run))
        return started

    def test_stop_releases_real_listener_and_a_new_proxy_can_bind_the_same_port(self):
        bound = threading.Event()
        ports = []
        original_start_server = asyncio.start_server

        async def start_server(*args, **kwargs):
            server = await original_start_server(*args, **kwargs)
            ports.append(server.sockets[0].getsockname()[1])
            bound.set()
            return server

        async def run(stop_event):
            self.controls.append((asyncio.get_running_loop(), stop_event))
            await tg_ws_proxy._run(stop_event)

        with patch.object(tray_common, "_run", run), \
                patch.object(tg_ws_proxy.asyncio, "start_server", start_server):
            self.assertTrue(tray_common.start_proxy(self.config, self.error))
            self.assertTrue(bound.wait(1))
            port = ports[-1]
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                client.settimeout(1)
                self.assertTrue(tray_common.stop_proxy())
                self.assertEqual(client.recv(1), b"")
            self.assertFalse(tray_common.proxy_running())
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.1)
            bound.clear()
            self.config["port"] = port
            self.assertTrue(tray_common.start_proxy(self.config, self.error))
            self.assertTrue(bound.wait(1))
            self.assertEqual(ports[-1], port)
            self.assertTrue(tray_common.stop_proxy())
        self.error.assert_not_called()

    def test_stop_during_event_loop_startup_is_remembered(self):
        entered, release = threading.Event(), threading.Event()
        self.gates.append(release)
        original_new_loop = asyncio.new_event_loop

        def delayed_loop():
            entered.set()
            release.wait(1)
            return original_new_loop()

        self.install_run()
        with patch.object(tray_common.asyncio, "new_event_loop", delayed_loop):
            tray_common.start_proxy(self.config, self.error)
            self.assertTrue(entered.wait(1))
            results = []
            stopper = self.original_thread(target=lambda: results.append(tray_common.stop_proxy()))
            stopper.start()
            try:
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    request = getattr(tray_common, "_proxy_stop_requested", None)
                    if request is not None and request.is_set():
                        break
                    if not stopper.is_alive():
                        break
                    time.sleep(0.001)
                release.set()
                stopper.join(timeout=1)
                self.assertEqual(results, [True])
                self.assertFalse(tray_common.proxy_running())
                self.assertFalse(self.workers[0].is_alive())
            finally:
                release.set()
                stopper.join(timeout=1)

    def test_timeout_retains_live_worker_and_restart_does_not_create_a_second_one(self):
        release = threading.Event()
        self.gates.append(release)

        async def stalled_shutdown(stop_event):
            while not release.is_set():
                await asyncio.sleep(0.002)

        started = self.install_run(stalled_shutdown)
        tray_common.start_proxy(self.config, self.error)
        self.assertTrue(started.wait(1))
        worker = tray_common._proxy_thread
        with self.assertLogs(tray_common.log, level="INFO") as messages:
            self.assertFalse(tray_common.stop_proxy())
            self.assertTrue(tray_common.proxy_running())
            self.assertIs(tray_common._proxy_thread, worker)
            self.assertFalse(tray_common.restart_proxy(self.config, self.error))
        self.assertEqual(len(self.workers), 1)
        self.assertFalse(any(record.getMessage() == "Proxy stopped" for record in messages.records))
        release.set()
        worker.join(timeout=1)
        self.assertTrue(tray_common.stop_proxy())
        self.assertFalse(tray_common.proxy_running())

    def test_concurrent_start_only_creates_one_worker(self):
        started = self.install_run()
        original_apply = tray_common.apply_proxy_config

        def delayed_apply(config):
            time.sleep(0.01)
            return original_apply(config)

        ready = threading.Barrier(4)
        results = []

        def launch():
            ready.wait(timeout=1)
            results.append(tray_common.start_proxy(self.config, self.error))

        with patch.object(tray_common, "apply_proxy_config", side_effect=delayed_apply):
            callers = [self.original_thread(target=launch) for _ in range(4)]
            for caller in callers:
                caller.start()
            for caller in callers:
                caller.join(timeout=1)
        self.assertTrue(started.wait(1))
        self.assertEqual(len(self.workers), 1)
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 3)
        self.assertTrue(tray_common.stop_proxy())

    def test_failed_start_stays_stopped_and_stop_is_idempotent(self):
        self.config["dc_ip"] = ["invalid"]
        self.assertFalse(tray_common.start_proxy(self.config, self.error))
        self.error.assert_called_once()
        self.assertFalse(self.workers)
        self.assertFalse(tray_common.proxy_running())
        self.assertTrue(tray_common.stop_proxy())
        self.assertTrue(tray_common.stop_proxy())


class AcceptedClientOwnershipTest(unittest.IsolatedAsyncioTestCase):
    async def exercise_listener(self, *, admit_at_stop):
        runtime = ProxyConfig(host="127.0.0.1", port=0, secret="a" * 32,
                              dc_redirects={}, pool_size=0, fallback_cfproxy=False,
                              cfproxy_h2_media=False)
        bound, accepted, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original_start, original_create, original_wait = (
            asyncio.start_server, asyncio.create_task, asyncio.wait)
        servers, callbacks, held, writers, tasks, peers = [], [], [], [], [], []
        active_before = tg_ws_proxy.stats.connections_active
        total_before = tg_ws_proxy.stats.connections_total
        runner = None

        def create_task(coro, *args, **kwargs):
            task = original_create(coro, *args, **kwargs)
            if getattr(coro, "cr_code", None) is tg_ws_proxy._handle_client.__code__:
                # An observer must not keep an otherwise orphaned writer alive.
                writers.append(weakref.ref(coro.cr_frame.f_locals["writer"]))
                tasks.append(task)
            return task

        async def start_server(callback, *args, **kwargs):
            callbacks.append(callback)

            def connected(reader, writer):
                if admit_at_stop:
                    held.append((reader, writer))
                else:
                    callback(reader, writer)
                accepted.set()

            server = await original_start(connected, *args, **kwargs)
            servers.append(server)
            bound.set()
            return server

        async def wait(waiters, *args, **kwargs):
            answer = await original_wait(waiters, *args, **kwargs)
            if asyncio.current_task() is runner and stop.is_set() and held:
                # Order the real accept callback immediately before _run sees
                # stop_event. Its original finally must cancel the new task
                # before its first coroutine step; the test never cancels it.
                reader, writer = held.pop()
                callbacks[0](reader, writer)
                del reader, writer
            return answer

        facts = {}
        with ExitStack() as stack:
            stack.enter_context(patch.object(tg_ws_proxy, "proxy_config", runtime))
            stack.enter_context(patch.object(tg_ws_proxy, "MAX_CLIENT_CONNECTIONS", 1))
            stack.enter_context(patch.object(tg_ws_proxy, "MAX_CLIENT_CONNECTIONS_PER_IP", 1))
            stack.enter_context(patch.object(tg_ws_proxy, "start_cfproxy_domain_refresh",
                                            side_effect=AssertionError("External refresh is forbidden")))
            stack.enter_context(patch.object(tg_ws_proxy.ws_pool, "warmup", AsyncMock()))
            stack.enter_context(patch.object(tg_ws_proxy.cf_worker_pool, "warmup", AsyncMock()))
            stack.enter_context(patch.object(asyncio, "start_server", start_server))
            stack.enter_context(patch.object(asyncio, "create_task", create_task))
            stack.enter_context(patch.object(asyncio, "wait", wait))
            try:
                runner = original_create(tg_ws_proxy._run(stop))
                await asyncio.wait_for(bound.wait(), 1)
                port = servers[0].sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                peers.append(writer)
                del writer
                await asyncio.wait_for(accepted.wait(), 1)
                if not admit_at_stop:
                    # A started client keeps the single admission slot until
                    # shutdown. A second real TCP connection must be rejected.
                    await asyncio.sleep(0)
                    self.assertEqual(len(tasks), 1)
                    self.assertEqual(tg_ws_proxy.stats.connections_active - active_before, 1)
                    rejected, writer = await asyncio.open_connection("127.0.0.1", port)
                    peers.append(writer)
                    del writer
                    self.assertEqual(await asyncio.wait_for(rejected.read(1), 1), b"")
                    self.assertEqual(len(tasks), 1)
                stop.set()
                try:
                    await asyncio.wait_for(asyncio.shield(runner), 1)
                    facts["stopped"] = True
                except asyncio.TimeoutError:
                    facts["stopped"] = False
                try:
                    facts["eof"] = await asyncio.wait_for(reader.read(1), 1) == b""
                except asyncio.TimeoutError:
                    facts["eof"] = False
                cells = dict(zip(callbacks[0].__code__.co_freevars, callbacks[0].__closure__))
                facts.update(handler_entered=tg_ws_proxy.stats.connections_total != total_before,
                             task_cancelled=tasks[0].cancelled(),
                             tracked=len(tg_ws_proxy._client_tasks),
                             per_ip=dict(cells["connections_per_ip"].cell_contents),
                             active=tg_ws_proxy.stats.connections_active - active_before,
                             held=len(held))
            finally:
                stop.set()
                for reference in writers:
                    writer = reference()
                    if writer is not None:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), 1)
                for _, writer in held:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), 1)
                held.clear()
                for writer in peers:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), 1)
                if runner is not None:
                    try:
                        await asyncio.wait_for(runner, 1)
                    except BaseException:
                        runner.cancel()
                        await asyncio.gather(runner, return_exceptions=True)
                for server in servers:
                    server.close()
                    await asyncio.wait_for(server.wait_closed(), 1)
                await asyncio.sleep(0)
                self.assertFalse(tg_ws_proxy._client_tasks)
                self.assertEqual(tg_ws_proxy.stats.connections_active, active_before)
                self.assertTrue(all(task.done() for task in tasks))
                self.assertTrue(runner is None or runner.done())
                self.assertTrue(all(not server.is_serving() and not server.sockets for server in servers))
                self.assertTrue(all(reference() is None or reference().is_closing() for reference in writers))
        return facts

    async def test_stop_closes_client_cancelled_before_its_first_step(self):
        facts = await self.exercise_listener(admit_at_stop=True)
        self.assertFalse(facts["handler_entered"])
        self.assertTrue(facts["task_cancelled"])
        self.assertEqual((facts["tracked"], facts["per_ip"], facts["active"], facts["held"]),
                         (0, {}, 0, 0))
        self.assertTrue(facts["eof"], "A cancelled, unstarted client retained its accepted socket")
        self.assertTrue(facts["stopped"], "The listener retained a cancelled client's transport")

    async def test_started_client_closes_and_releases_its_admission_slot(self):
        facts = await self.exercise_listener(admit_at_stop=False)
        self.assertTrue(facts["handler_entered"])
        self.assertTrue(facts["eof"])
        self.assertTrue(facts["stopped"])
        self.assertEqual((facts["tracked"], facts["per_ip"], facts["active"]), (0, {}, 0))


if __name__ == "__main__":
    unittest.main()
