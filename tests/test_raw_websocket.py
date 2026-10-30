import asyncio
import base64
import datetime
import hashlib
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from proxy.raw_websocket import RawWebSocket, WsHandshakeError, _xor_mask
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _raw_frame(opcode, data, fin=True):
    b0 = (0x80 if fin else 0x00) | opcode
    n = len(data)
    if n < 126:
        return bytes([b0, n]) + data
    if n < 65536:
        return bytes([b0, 126]) + n.to_bytes(2, 'big') + data
    return bytes([b0, 127]) + n.to_bytes(8, 'big') + data


class _NullWriter:
    def write(self, data):
        pass

    async def drain(self):
        pass


def _recv(chunks, cls=RawWebSocket):
    async def _run():
        reader = asyncio.StreamReader()
        for chunk in chunks:
            reader.feed_data(chunk)
        reader.feed_eof()
        ws = cls(reader, _NullWriter())
        return ws, await ws.recv()

    return asyncio.run(_run())


class XorMaskTest(unittest.TestCase):
    def test_matches_bytewise_xor_at_fast_path_and_frame_boundaries(self):
        for length in (0, 1, 2, 3, 4, 5, 125, 126, 127, 255, 511, 512, 513, 514, 515,
                       16384, 65535, 65536, 65537, 1024 * 1024 + 3):
            data = (bytes(range(256)) * (length // 256 + 1))[:length]
            for mask in (b'\x00' * 4, b'\xff' * 4, b'\x01\x7f\x80\xff'):
                with self.subTest(length=length, mask=mask):
                    expected = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
                    self.assertEqual(_xor_mask(data, mask), expected)

    def test_roundtrip(self):
        data = bytes(range(256)) * 3
        mask = b'\x01\x02\x03\x04'
        self.assertEqual(_xor_mask(_xor_mask(data, mask), mask), data)

    def test_empty_payload(self):
        self.assertEqual(_xor_mask(b'', b'\x01\x02\x03\x04'), b'')


class BuildFrameTest(unittest.TestCase):
    def test_masked_frame_wire_format_across_all_length_encodings(self):
        mask = b'\x01\x7f\x80\xff'
        for length in (1, 125, 126, 511, 512, 513, 65535, 65536, 65537):
            payload = (bytes(range(256)) * (length // 256 + 1))[:length]
            with self.subTest(length=length), patch('proxy.raw_websocket.os.urandom', return_value=mask):
                frame = RawWebSocket._build_frame(RawWebSocket.OP_BINARY, payload, mask=True)
                if length < 126:
                    header = bytes([0x82, 0x80 | length])
                elif length < 65536:
                    header = b'\x82\xfe' + length.to_bytes(2, 'big')
                else:
                    header = b'\x82\xff' + length.to_bytes(8, 'big')
                masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
                self.assertEqual(frame, header + mask + masked)

    def test_short_unmasked_frame(self):
        self.assertEqual(
            RawWebSocket._build_frame(RawWebSocket.OP_BINARY, b'abc'),
            b'\x82\x03abc',
        )

    def test_extended_length_selects_16bit_header(self):
        frame = RawWebSocket._build_frame(RawWebSocket.OP_BINARY, b'x' * 200)
        self.assertEqual(frame[:2], b'\x82\x7e')
        self.assertEqual(int.from_bytes(frame[2:4], 'big'), 200)

    def test_masked_frame_sets_mask_bit_and_is_reversible(self):
        payload = b'payload'
        frame = RawWebSocket._build_frame(
            RawWebSocket.OP_BINARY, payload, mask=True)
        self.assertTrue(frame[1] & 0x80)
        self.assertEqual(_xor_mask(frame[6:], frame[2:6]), payload)


class RecvTest(unittest.TestCase):
    def test_returns_unfragmented_message(self):
        _, msg = _recv([_raw_frame(RawWebSocket.OP_BINARY, b'hello')])
        self.assertEqual(msg, b'hello')

    def test_reassembles_fragmented_message(self):
        _, msg = _recv([
            _raw_frame(RawWebSocket.OP_BINARY, b'AAA', False),
            _raw_frame(RawWebSocket.OP_CONT, b'BBB', False),
            _raw_frame(RawWebSocket.OP_CONT, b'CCC', True),
        ])
        self.assertEqual(msg, b'AAABBBCCC')

    def test_control_frame_between_fragments_is_skipped(self):
        _, msg = _recv([
            _raw_frame(RawWebSocket.OP_BINARY, b'AAA', False),
            _raw_frame(RawWebSocket.OP_PONG, b''),
            _raw_frame(RawWebSocket.OP_CONT, b'BBB', True),
        ])
        self.assertEqual(msg, b'AAABBB')

    def test_empty_first_fragment_keeps_message_state(self):
        _, msg = _recv([
            _raw_frame(RawWebSocket.OP_BINARY, b'', False),
            _raw_frame(RawWebSocket.OP_PING, b'ping'),
            _raw_frame(RawWebSocket.OP_CONT, b'content'),
        ])
        self.assertEqual(msg, b'content')

    def test_invalid_fragment_sequences_are_rejected(self):
        for frames in (
            [_raw_frame(RawWebSocket.OP_CONT, b'orphan')],
            [_raw_frame(RawWebSocket.OP_BINARY, b'first', False),
             _raw_frame(RawWebSocket.OP_BINARY, b'second')],
            [_raw_frame(RawWebSocket.OP_BINARY, b'', False),
             _raw_frame(RawWebSocket.OP_BINARY, b'second')],
        ):
            with self.subTest(frames=frames), self.assertRaises(ConnectionError):
                _recv(frames)

    def test_invalid_frame_header_is_rejected_before_payload_read(self):
        for header in (
            b'\xc2\x01',  # Unnegotiated RSV1.
            b'\x82\x81',  # A masked server frame.
            b'\x83\x01',  # Reserved opcode.
            b'\x81\x01',  # Text is not the binary subprotocol.
            b'\x09\x01',  # Fragmented ping.
            b'\x89\x7e',  # Control payload over 125 bytes.
            b'\x82\x7e\x00\x01',  # Non-minimal length encoding.
            b'\x82\x7f' + (126).to_bytes(8, 'big'),
            b'\x82\x7f' + (1 << 63).to_bytes(8, 'big'),
        ):
            with self.subTest(header=header), self.assertRaises(ConnectionError):
                _recv([header])

    def test_invalid_close_payload_is_rejected(self):
        for payload in (b'x', b'\x03\xed', b'\x03\xee', b'\x03\xe8\xff',
                        (2999).to_bytes(2, 'big'), (5000).to_bytes(2, 'big')):
            with self.subTest(payload=payload), self.assertRaises(ConnectionError):
                _recv([_raw_frame(RawWebSocket.OP_CLOSE, payload)])

    def test_close_frame_returns_none(self):
        ws, msg = _recv([_raw_frame(RawWebSocket.OP_CLOSE, b'\x03\xe8')])
        self.assertIsNone(msg)
        self.assertTrue(ws._closed)

    def test_oversized_frame_is_rejected_before_reading_payload(self):
        header = bytes([0x82, 127]) + (1 << 40).to_bytes(8, 'big')
        with self.assertRaises(ConnectionError):
            _recv([header])

    def test_reassembled_message_exceeding_limit_is_rejected(self):
        class _Capped(RawWebSocket):
            __slots__ = ()
            MAX_MESSAGE_LEN = 1500

        chunk = b'x' * 1024
        with self.assertRaises(ConnectionError):
            _recv([
                _raw_frame(RawWebSocket.OP_BINARY, chunk, False),
                _raw_frame(RawWebSocket.OP_CONT, chunk, False),
            ], cls=_Capped)


class ParseCloseTest(unittest.TestCase):
    def test_known_code_gets_name(self):
        code, reason = RawWebSocket._parse_close(b'\x03\xe8bye')
        self.assertEqual(code, 1000)
        self.assertIn('normal', reason)

    def test_empty_payload(self):
        self.assertEqual(RawWebSocket._parse_close(b''), (None, ''))


class CloseCleanupTest(unittest.IsolatedAsyncioTestCase):
    async def test_real_peer_valid_fragments_ping_and_invalid_control(self):
        accepted = asyncio.get_running_loop().create_future()
        server = await asyncio.start_server(
            lambda reader, writer: accepted.set_result((reader, writer)), '127.0.0.1', 0)
        writer = peer_writer = None
        try:
            reader, writer = await asyncio.open_connection(
                '127.0.0.1', server.sockets[0].getsockname()[1])
            peer_reader, peer_writer = await accepted
            peer_writer.write(_raw_frame(RawWebSocket.OP_BINARY, b'', False)
                              + _raw_frame(RawWebSocket.OP_PING, b'ping')
                              + _raw_frame(RawWebSocket.OP_CONT, b'data'))
            await peer_writer.drain()
            ws = RawWebSocket(reader, writer)
            self.assertEqual(await asyncio.wait_for(ws.recv(), 1), b'data')
            pong_header = await asyncio.wait_for(peer_reader.readexactly(6), 1)
            self.assertEqual(pong_header[:2], b'\x8a\x84')
            self.assertEqual(_xor_mask(await peer_reader.readexactly(4), pong_header[2:]), b'ping')
            # Only a two-byte oversized control header: fail promptly, without
            # waiting for extended length or a potentially enormous body.
            peer_writer.write(b'\x89\x7f')
            await peer_writer.drain()
            with self.assertRaises(ConnectionError):
                await asyncio.wait_for(ws.recv(), 1)
            await ws.close()
            self.assertTrue(writer.is_closing())
            await asyncio.wait_for(peer_reader.read(), 1)
        finally:
            for stream in (writer, peer_writer):
                if stream is not None:
                    stream.close()
                    await stream.wait_closed()
            server.close()
            await server.wait_closed()

    async def test_received_close_replies_once_and_peer_observes_eof(self):
        accepted = asyncio.get_running_loop().create_future()
        server = await asyncio.start_server(
            lambda reader, writer: accepted.set_result((reader, writer)),
            '127.0.0.1', 0)
        writer = peer_writer = None
        try:
            reader, writer = await asyncio.open_connection(
                '127.0.0.1', server.sockets[0].getsockname()[1])
            peer_reader, peer_writer = await asyncio.wait_for(accepted, 1)
            peer_writer.write(_raw_frame(RawWebSocket.OP_CLOSE, b'\x03\xe8bye'))
            await peer_writer.drain()

            ws = RawWebSocket(reader, writer)
            mask = b'\x01\x02\x03\x04'
            with patch('proxy.raw_websocket.os.urandom', return_value=mask):
                self.assertIsNone(await asyncio.wait_for(ws.recv(), 1))
                await ws.close()
                await ws.close()

            reply = await asyncio.wait_for(peer_reader.read(), 1)
            self.assertEqual(reply, b'\x88\x82' + mask + _xor_mask(b'\x03\xe8', mask))
            self.assertTrue(writer.is_closing())
        finally:
            for stream in (writer, peer_writer):
                if stream is not None:
                    stream.close()
                    await stream.wait_closed()
            server.close()
            await server.wait_closed()

    async def test_local_close_is_idempotent(self):
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        ws = RawWebSocket(None, writer)

        await ws.close()
        await ws.close()

        writer.write.assert_called_once()
        writer.drain.assert_awaited_once()
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()
        with self.assertRaises(ConnectionError):
            await ws.send(b'data')

    async def test_failed_close_frame_still_closes_transport(self):
        for received in (False, True):
            for operation in ('write', 'drain'):
                with self.subTest(received=received, operation=operation):
                    reader = asyncio.StreamReader()
                    reader.feed_data(_raw_frame(RawWebSocket.OP_CLOSE, b'\x03\xe8'))
                    writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
                    getattr(writer, operation).side_effect = OSError('closed peer')
                    ws = RawWebSocket(reader, writer)

                    await (ws.recv() if received else ws.close())
                    await ws.close()

                    writer.write.assert_called_once()
                    writer.close.assert_called_once()
                    writer.wait_closed.assert_not_awaited()
                    writer.transport.abort.assert_called_once()

    async def test_cancelled_close_frame_still_closes_transport(self):
        for received in (False, True):
            with self.subTest(received=received):
                reader = asyncio.StreamReader()
                reader.feed_data(_raw_frame(RawWebSocket.OP_CLOSE, b'\x03\xe8'))
                started = asyncio.Event()

                async def drain():
                    started.set()
                    await asyncio.Future()

                writer = Mock(drain=AsyncMock(side_effect=drain),
                              wait_closed=AsyncMock())
                ws = RawWebSocket(reader, writer)
                task = asyncio.create_task(ws.recv() if received else ws.close())
                await asyncio.wait_for(started.wait(), 1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                await ws.close()

                writer.write.assert_called_once()
                writer.close.assert_called_once()
                writer.wait_closed.assert_not_awaited()
                writer.transport.abort.assert_called_once()

    async def test_stalled_close_cleanup_aborts_after_deadline(self):
        class _ShortClose(RawWebSocket):
            CLOSE_TIMEOUT = 0.01

        for received in (False, True):
            for operation in ('drain', 'wait_closed'):
                with self.subTest(received=received, operation=operation):
                    reader = asyncio.StreamReader()
                    reader.feed_data(_raw_frame(RawWebSocket.OP_CLOSE, b'\x03\xe8'))
                    writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())

                    async def stall():
                        await asyncio.Future()

                    getattr(writer, operation).side_effect = stall
                    ws = _ShortClose(reader, writer)
                    await asyncio.wait_for(ws.recv() if received else ws.close(), 1)
                    await ws.close()

                    writer.close.assert_called_once()
                    writer.transport.abort.assert_called_once()
                    getattr(writer, operation).assert_awaited_once()

    async def test_cancelled_tls_shutdown_aborts_transport(self):
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        started = asyncio.Event()

        async def wait_closed():
            started.set()
            await asyncio.Future()

        writer.wait_closed.side_effect = wait_closed
        ws = RawWebSocket(None, writer)
        task = asyncio.create_task(ws.close())
        await asyncio.wait_for(started.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        writer.close.assert_called_once()
        writer.transport.abort.assert_called_once()


class HandshakeErrorTest(unittest.TestCase):
    def test_redirect_status_codes(self):
        for code in (301, 302, 303, 307, 308):
            self.assertTrue(WsHandshakeError(code, '').is_redirect)
        for code in (0, 200, 429, 502):
            self.assertFalse(WsHandshakeError(code, '').is_redirect)


class HandshakeCleanupTest(unittest.IsolatedAsyncioTestCase):
    async def test_cancelling_pending_upgrade_closes_socket(self):
        reader = asyncio.StreamReader()
        writer = Mock(drain=AsyncMock())
        started = asyncio.Event()

        async def drain():
            started.set()

        writer.drain.side_effect = drain
        with patch('proxy.raw_websocket.asyncio.open_connection',
                   AsyncMock(return_value=(reader, writer))), \
                patch('proxy.raw_websocket.set_sock_opts'):
            task = asyncio.create_task(RawWebSocket.connect('example.org', 'example.org'))
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        writer.close.assert_called_once()

    async def test_failed_upgrade_closes_socket(self):
        for error in (ConnectionResetError(), asyncio.TimeoutError()):
            with self.subTest(error=type(error)):
                reader = Mock(readline=AsyncMock(side_effect=error))
                writer = Mock(drain=AsyncMock())
                with patch('proxy.raw_websocket.asyncio.open_connection',
                           AsyncMock(return_value=(reader, writer))), \
                        patch('proxy.raw_websocket.set_sock_opts'):
                    with self.assertRaises(type(error)):
                        await RawWebSocket.connect('example.org', 'example.org')
                writer.close.assert_called_once()


def _valid_upgrade(key):
    accept = base64.b64encode(hashlib.sha1(
        key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
    return (b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
            b'Connection: keep-alive, Upgrade\r\nSec-WebSocket-Protocol: binary\r\n'
            b'Sec-WebSocket-Accept: ' + accept + b'\r\n\r\n')


class HandshakeSecurityTest(unittest.IsolatedAsyncioTestCase):
    async def mocked_upgrade(self, response, **kwargs):
        reader = asyncio.StreamReader()
        reader.feed_data(response)
        writer = Mock(drain=AsyncMock(), wait_closed=AsyncMock())
        with patch('proxy.raw_websocket.asyncio.open_connection',
                   AsyncMock(return_value=(reader, writer))), \
                patch('proxy.raw_websocket.set_sock_opts'), \
                patch('proxy.raw_websocket.os.urandom', return_value=b'a' * 16):
            try:
                return await RawWebSocket.connect('example.org', 'example.org', **kwargs)
            except BaseException:
                writer.close.assert_called_once()
                raise

    async def test_valid_upgrade_is_accepted(self):
        result = await self.mocked_upgrade(_valid_upgrade(base64.b64encode(b'a' * 16)))
        self.assertIsInstance(result, RawWebSocket)

    async def test_status_line_requires_http11_and_a_three_digit_ascii_code(self):
        good = _valid_upgrade(base64.b64encode(b'a' * 16))
        for status in (b'NOTHTTP 101 Switching Protocols',
                       b'HTTP/1.0 101 Switching Protocols',
                       b'HTTP/2 101 Switching Protocols',
                       b' HTTP/1.1 101 Switching Protocols',
                       b'HTTP/1.1 +101 Switching Protocols',
                       b'HTTP/1.1 0101 Switching Protocols',
                       b'HTTP/1.1\t101 Switching Protocols',
                       b'HTTP/1.1  101 Switching Protocols'):
            with self.subTest(status=status), self.assertRaises(WsHandshakeError):
                await self.mocked_upgrade(good.replace(
                    b'HTTP/1.1 101 Switching Protocols', status))

    async def test_incorrect_or_missing_accept_and_subprotocol_are_rejected(self):
        good = _valid_upgrade(base64.b64encode(b'a' * 16))
        malformed = [b'HTTP/1.1 101 Switching Protocols\r\n\r\n',
                     good.replace(b'Sec-WebSocket-Accept: ', b'Sec-WebSocket-Accept: wrong'),
                     good.replace(b'Protocol: binary', b'Protocol: text'),
                     good.replace(b'Upgrade: websocket', b'Upgrade: h2c'),
                     good.replace(b'Connection: keep-alive, Upgrade', b'Connection: close')]
        for response in malformed:
            with self.subTest(response=response), self.assertRaises(WsHandshakeError):
                await self.mocked_upgrade(response)

    async def test_many_short_response_headers_cannot_grow_without_limit(self):
        with self.assertRaisesRegex(WsHandshakeError, 'headers too large'):
            await self.mocked_upgrade(b'HTTP/1.1 101 Switching Protocols\r\n'
                                      + b'X-Padding: ' + b'a' * 100 + b'\r\n'
                                      + (b'X: ' + b'a' * 100 + b'\r\n') * 400)

    async def test_slow_headers_share_a_single_handshake_deadline(self):
        async def slow_line():
            await asyncio.sleep(0.02)
            return b'X-Padding: still-here\r\n'
        reader = Mock(readline=AsyncMock(side_effect=slow_line))
        writer = Mock(drain=AsyncMock())
        with patch('proxy.raw_websocket.asyncio.open_connection',
                   AsyncMock(return_value=(reader, writer))), \
                patch('proxy.raw_websocket.set_sock_opts'):
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(RawWebSocket.connect(
                    'example.org', 'example.org', timeout=0.05), 0.2)
        writer.close.assert_called_once()
        self.assertLess(reader.readline.await_count, 10)

    async def test_fronting_verifies_actual_origin_even_when_sni_differs(self):
        for certified_name, origin, accepted in (
                ('kws2.web.telegram.org', 'kws2.web.telegram.org', True),
                ('*.web.telegram.org', 'kws2.web.telegram.org', True),
                ('telegram.org', 'kws2.web.telegram.org', True),
                ('telegram.org', 'configured.example', False),
                ('attacker.example', 'kws2.web.telegram.org', False)):
            with self.subTest(certified_name=certified_name), tempfile.TemporaryDirectory() as tmp:
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                now = datetime.datetime.now(datetime.timezone.utc)
                subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                                       certified_name)])
                cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                        .public_key(key.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(now - datetime.timedelta(minutes=1))
                        .not_valid_after(now + datetime.timedelta(days=1))
                        .add_extension(x509.SubjectAlternativeName([x509.DNSName(certified_name)]),
                                       critical=False)
                        .sign(key, hashes.SHA256()))
                cert_path, key_path = Path(tmp) / 'cert.pem', Path(tmp) / 'key.pem'
                cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
                key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.load_cert_chain(cert_path, key_path)
                trusted = ssl.create_default_context(cafile=str(cert_path))
                trusted.check_hostname = False
                self.assertEqual(trusted.verify_mode, ssl.CERT_REQUIRED)
                requests = []
                finished = asyncio.Event()

                async def peer(reader, writer):
                    try:
                        request = await reader.readuntil(b'\r\n\r\n')
                        requests.append(request)
                        ws_key = next(line.split(b': ', 1)[1] for line in request.split(b'\r\n')
                                      if line.startswith(b'Sec-WebSocket-Key: '))
                        writer.write(_valid_upgrade(ws_key))
                        await writer.drain()
                        await reader.read()
                    except (asyncio.IncompleteReadError, ConnectionError):
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()
                        finished.set()

                server = await asyncio.start_server(peer, '127.0.0.1', 0, ssl=server_context)
                real_open = asyncio.open_connection

                async def local_connection(host, port, **options):
                    self.assertEqual(options['server_hostname'], 'sprinthost.ru')
                    return await real_open('127.0.0.1', server.sockets[0].getsockname()[1], **options)

                try:
                    with patch('proxy.raw_websocket._ssl_ctx_fronting', trusted), \
                            patch('proxy.raw_websocket.asyncio.open_connection', local_connection):
                        if accepted:
                            ws = await RawWebSocket.connect('149.154.167.220' if origin.endswith('.telegram.org') else origin, origin,
                                                            sni='sprinthost.ru')
                            ws.writer.close()
                            await ws.writer.wait_closed()
                        else:
                            with self.assertRaises(ssl.SSLCertVerificationError):
                                await RawWebSocket.connect('149.154.167.220' if origin.endswith('.telegram.org') else origin, origin,
                                                           sni='sprinthost.ru')
                    await asyncio.wait_for(finished.wait(), 1)
                    self.assertEqual(bool(requests), accepted)
                finally:
                    server.close()
                    await server.wait_closed()


if __name__ == '__main__':
    unittest.main()
