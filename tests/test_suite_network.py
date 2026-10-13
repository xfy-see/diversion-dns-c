"""Deterministic loopback-only protocol fixtures; no C build or public endpoint."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('suite_network', Path(__file__).resolve().parents[1] / 'scripts/suite_network.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def read_exact(sock, length):
    data = b''
    while len(data) < length:
        block = sock.recv(length - len(data))
        if not block:
            raise EOFError('fixture EOF')
        data += block
    return data


def dns_response(query, address='192.0.2.9', rcode=0):
    qtype = struct.unpack('!H', query[-4:-2])[0]
    packed = socket.inet_pton(socket.AF_INET if qtype == 1 else socket.AF_INET6,
                              address if qtype == 1 else '2001:db8::9')
    answer = b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 30, len(packed)) + packed
    return query[:2] + struct.pack('!5H', 0x8180 | rcode, 1, int(rcode == 0), 0, 0) + query[12:] + (answer if rcode == 0 else b'')


class Server:
    def __init__(self, handler, udp=False, family=4):
        self.handler, self.udp, self.family = handler, udp, family
        self.sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6,
                                  socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.sock.bind(('127.0.0.1' if family == 4 else '::1', 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(3)
        if not udp:
            self.sock.listen(1)
        self.errors = []
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            if self.udp:
                query, peer = self.sock.recvfrom(65536)
                self.sock.sendto(self.handler(query), peer)
            else:
                connection, _ = self.sock.accept()
                with connection:
                    connection.settimeout(3)
                    self.handler(connection)
        except (BrokenPipeError, ConnectionResetError, EOFError):
            pass
        except Exception as exc:
            self.errors.append(exc)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.thread.join(4)
        self.sock.close()
        if self.thread.is_alive():
            raise AssertionError('fixture server did not stop')
        if self.errors:
            raise self.errors[0]


def ws_headers(sock, bad=False):
    header = b''
    while not header.endswith(b'\r\n\r\n'):
        header += read_exact(sock, 1)
    lines = header.decode().split('\r\n')
    values = dict(line.split(': ', 1) for line in lines[1:] if ': ' in line)
    accept = base64.b64encode(hashlib.sha1((values['Sec-WebSocket-Key'] + probe.GUID).encode()).digest()).decode()
    reply = ('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n'
             'Sec-WebSocket-Accept: %s\r\n\r\n' % ('invalid' if bad else accept)).encode()
    # Header split checks buffering; a frame may arrive in the same TCP read.
    sock.sendall(reply[:7])
    sock.sendall(reply[7:])
    return values


def ws_client_frame(sock):
    first, second = read_exact(sock, 2)
    if not first & 0x80 or not second & 0x80:
        raise AssertionError('client frame is not final and masked')
    length = second & 127
    if length > 125:
        raise AssertionError('fixture expects control frames only')
    mask = read_exact(sock, 4)
    payload = read_exact(sock, length)
    return first & 15, bytes(value ^ mask[index % 4] for index, value in enumerate(payload))


def ws_echo(sock):
    ws_headers(sock)
    while True:
        opcode, payload = ws_client_frame(sock)
        if opcode == 9:
            frame = bytes([0x8a, len(payload)]) + payload
            sock.sendall(frame[:1])
            time.sleep(0.001)
            sock.sendall(frame[1:])
        elif opcode == 8:
            sock.sendall(bytes([0x88, len(payload)]) + payload)
            return
        elif opcode != 10:
            raise AssertionError('unexpected client opcode')


class DNSTests(unittest.TestCase):
    def query(self, port, **extra):
        return dict({'server': '127.0.0.1', 'port': port, 'family': 4, 'name': 'answer.test',
                     'qtype': 'A', 'timeout': 1}, **extra)

    def test_udp_a_checks_answers(self):
        with Server(dns_response, udp=True) as server:
            result = probe.dns_query(self.query(server.port, expect_addresses=['192.0.2.9']))
        self.assertEqual(result['addresses'][0]['address'], '192.0.2.9')
        self.assertEqual(result['transport_family'], 4)
        self.assertGreater(result['local_port'], 0)

    def test_aaaa_over_ipv4_is_distinct_from_transport_ipv6(self):
        with Server(dns_response, udp=True) as server:
            result = probe.dns_query(self.query(server.port, qtype='AAAA'))
        self.assertEqual(result['addresses'][0]['address'], '2001:db8::9')
        self.assertEqual(result['transport_family'], 4)
        self.assertEqual(result['qtype'], 'AAAA')

    def test_tcp_partial_length_and_payload(self):
        def handler(sock):
            length = struct.unpack('!H', read_exact(sock, 2))[0]
            reply = dns_response(read_exact(sock, length))
            frame = struct.pack('!H', len(reply)) + reply
            for part in (frame[:1], frame[1:3], frame[3:20], frame[20:]):
                sock.sendall(part)
        with Server(handler) as server:
            result = probe.dns_query(self.query(server.port, transport='tcp'))
        self.assertEqual(result['transport'], 'tcp')

    def test_udp_ipv6_transport_if_available(self):
        try:
            server = Server(dns_response, udp=True, family=6)
        except OSError:
            self.skipTest('IPv6 loopback unavailable')
        with server:
            result = probe.dns_query(self.query(server.port, server='::1', family=6))
        self.assertEqual(result['transport_family'], 6)

    def test_tcp_short_frame_fails(self):
        with Server(lambda sock: (sock.recv(1024), sock.sendall(b'\0\x20short'))) as server:
            with self.assertRaisesRegex(probe.ProbeError, 'EOF'):
                probe.dns_query(self.query(server.port, transport='tcp'))

    def test_wrong_id_question_truncated_flag_and_address(self):
        query = struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + probe._dns_name('answer.test')[1] + struct.pack('!HH', 1, 1)
        packet = dns_response(query)
        changes = [b'\0\x7c' + packet[2:], packet[:2] + b'\x83\x80' + packet[4:],
                   packet[:13] + b'x' + packet[14:], packet[:-1]]
        for changed in changes:
            with self.subTest(changed=changed.hex()), self.assertRaises(probe.ProbeError):
                probe.parse_dns(changed, 123, 'answer.test', 'A')

    def test_compression_cycle_and_nonanswer_owner(self):
        with self.assertRaisesRegex(probe.ProbeError, 'compression'):
            probe._read_name(b'\xc0\0', 0)
        query = struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + probe._dns_name('answer.test')[1] + struct.pack('!HH', 1, 1)
        packet = dns_response(query)
        answer_start = len(query)
        packet = packet[:answer_start] + probe._dns_name('unrelated.test')[1] + packet[answer_start + 2:]
        with self.assertRaisesRegex(probe.ProbeError, 'no matching'):
            probe.parse_dns(packet, 123, 'answer.test', 'A')

    def test_negative_answer_explicit_expected_rcode(self):
        with Server(lambda q: dns_response(q, rcode=3), udp=True) as server:
            result = probe.dns_query(self.query(server.port, expected_rcode=3))
        self.assertEqual(result['rcode'], 3)
        self.assertEqual(result['addresses'], [])

    def test_dns_server_must_be_literal_matching_family(self):
        for item in (self.query(53, server='example.test'), self.query(53, family=6)):
            with self.subTest(item=item), self.assertRaises(probe.ProbeError):
                probe.dns_query(item)

    def test_cname_answer_chain(self):
        qname, wire = probe._dns_name('answer.test')
        target = probe._dns_name('canonical.test')[1]
        header = struct.pack('!6H', 123, 0x8180, 1, 2, 0, 0)
        question = wire + struct.pack('!HH', 1, 1)
        cname = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 60, len(target)) + target
        answer = target + struct.pack('!HHIH', 1, 1, 30, 4) + b'\xc0\x00\x02\x09'
        result = probe.parse_dns(header + question + cname + answer, 123, qname, 'A')
        self.assertEqual(result['addresses'][0]['owner'], 'canonical.test')


class HTTPTests(unittest.TestCase):
    def test_custom_dns_connect_preserves_host_and_ignores_proxy(self):
        request = []
        def handler(sock):
            request.append(sock.recv(8192))
            sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nokay')
        with Server(handler) as server, Server(lambda q: dns_response(q, '127.0.0.1'), udp=True) as dns:
            with patch.dict('os.environ', {'HTTP_PROXY': 'http://127.0.0.1:1', 'ALL_PROXY': 'http://127.0.0.1:1'}):
                result = probe.http_probe({'url': 'http://fixture.test:%s/path?q=1' % server.port,
                                           'dns_server': '127.0.0.1', 'dns_port': dns.port, 'timeout': 1})
        self.assertIn(('Host: fixture.test:%s\r\n' % server.port).encode(), request[0])
        self.assertEqual(result['peer'], '127.0.0.1')
        self.assertEqual(result['body_sample_sha256'], hashlib.sha256(b'okay').hexdigest())
        self.assertFalse(result['system_proxy_used'])

    def test_http_chunked_partial_response(self):
        def handler(sock):
            sock.recv(8192)
            for part in (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n', b'4\r\nhe', b'll\r\n1\r\no\r\n0\r\n\r\n'):
                sock.sendall(part)
        with Server(handler) as server:
            result = probe.http_probe({'url': 'http://127.0.0.1:%s/' % server.port})
        self.assertEqual(result['body_sample_sha256'], hashlib.sha256(b'hello').hexdigest())

    def test_chunked_missing_terminator_fails(self):
        def handler(sock):
            sock.recv(8192)
            sock.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n')
        with Server(handler) as server:
            with self.assertRaisesRegex(probe.ProbeError, 'EOF'):
                probe.http_probe({'url': 'http://127.0.0.1:%s/' % server.port})

    def test_bounded_body_is_explicitly_incomplete(self):
        def handler(sock):
            sock.recv(8192)
            sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nokay')
        with Server(handler) as server:
            result = probe.http_probe({'url': 'http://127.0.0.1:%s/' % server.port, 'max_bytes': 2})
        self.assertEqual(result['body_sample_bytes'], 2)
        self.assertFalse(result['body_complete'])
        self.assertTrue(result['body_limit_reached'])

    def test_ipv6_http_host_header_if_available(self):
        requests = []
        def handler(sock):
            requests.append(sock.recv(8192))
            sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        try:
            server = Server(handler, family=6)
        except OSError:
            self.skipTest('IPv6 loopback unavailable')
        with server:
            result = probe.http_probe({'url': 'http://[::1]:%s/' % server.port, 'answer_family': 6})
        self.assertIn(('Host: [::1]:%s\r\n' % server.port).encode(), requests[0])
        self.assertEqual(result['answer_family'], 6)
        self.assertTrue(result['body_complete'])

    def test_http_incomplete_body_fails(self):
        def handler(sock):
            sock.recv(8192)
            sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\nshort')
        with Server(handler) as server:
            with self.assertRaisesRegex(probe.ProbeError, 'EOF'):
                probe.http_probe({'url': 'http://127.0.0.1:%s/' % server.port})

    def test_hostname_requires_custom_dns_and_rejects_credentials(self):
        for url in ('http://fixture.test/', 'http://user:pass@127.0.0.1/', 'http://127.0.0.1/\r\nX: bad'):
            with self.subTest(url=url), self.assertRaises(probe.ProbeError):
                probe.http_probe({'url': url})

    def test_tls_uses_default_verified_context_and_original_sni(self):
        with patch.object(probe.socket, 'socket') as socket_factory, patch.object(probe.ssl, 'create_default_context') as context_factory:
            result = probe._connect({'answer_family': 4}, '192.0.2.9', 443, 'fixture.test', True, time.monotonic() + 1)
        context_factory.assert_called_once_with(cafile=None)
        context_factory.return_value.wrap_socket.assert_called_once_with(socket_factory.return_value, server_hostname='fixture.test')
        self.assertIs(result, context_factory.return_value.wrap_socket.return_value)


class WebSocketTests(unittest.TestCase):
    def config(self, port, **extra):
        return dict({'url': 'ws://127.0.0.1:%s/' % port, 'duration': .10, 'ping_interval': .025,
                     'timeout': .1}, **extra)

    def test_partial_handshake_masked_pings_matching_pongs_graceful_close(self):
        with Server(ws_echo) as server:
            result = probe.websocket_probe(self.config(server.port))
        self.assertGreaterEqual(result['ping_count'], 3)
        self.assertTrue(result['close_acknowledged'])
        self.assertGreaterEqual(result['observed_duration_seconds'], .10)
        self.assertEqual(len(result['events']), result['ping_count'])

    def test_bad_accept_fails_and_retains_partial_evidence(self):
        with Server(lambda sock: ws_headers(sock, bad=True)) as server:
            result = probe.run_suite({'websocket': [self.config(server.port)]})
        self.assertEqual(result['status'], 'fail')
        self.assertIn('Accept mismatch', result['results'][0]['reason'])
        self.assertIn('pong_samples', result['results'][0]['detail'])

    def test_server_close_fails_before_duration(self):
        def handler(sock):
            ws_headers(sock)
            ws_client_frame(sock)
            sock.sendall(b'\x88\x02\x03\xe8')
        with Server(handler) as server:
            with self.assertRaisesRegex(probe.ProbeError, 'closed before'):
                probe.websocket_probe(self.config(server.port))

    def test_wrong_pong_does_not_satisfy_ping(self):
        def handler(sock):
            ws_headers(sock)
            ws_client_frame(sock)
            sock.sendall(b'\x8a\x05wrong')
            time.sleep(.15)
        with Server(handler) as server:
            with self.assertRaisesRegex(probe.ProbeError, 'pong timeout'):
                probe.websocket_probe(self.config(server.port))

    def test_masked_server_frame_rejected(self):
        def handler(sock):
            ws_headers(sock)
            ws_client_frame(sock)
            sock.sendall(b'\x8a\x80abcd')
        with Server(handler) as server:
            with self.assertRaisesRegex(probe.ProbeError, 'must not be masked'):
                probe.websocket_probe(self.config(server.port))

    def test_server_ping_receives_masked_pong(self):
        def handler(sock):
            ws_headers(sock)
            sock.sendall(b'\x89\x04serv')
            while True:
                opcode, payload = ws_client_frame(sock)
                if opcode == 9:
                    sock.sendall(bytes([0x8a, len(payload)]) + payload)
                elif opcode == 10:
                    self.assertEqual(payload, b'serv')
                elif opcode == 8:
                    sock.sendall(bytes([0x88, len(payload)]) + payload)
                    return
        with Server(handler) as server:
            result = probe.websocket_probe(self.config(server.port))
        self.assertEqual(result['server_pings'], 1)

    def test_invalid_continuation_rejected(self):
        def handler(sock):
            ws_headers(sock)
            ws_client_frame(sock)
            sock.sendall(b'\x80\0')
        with Server(handler) as server:
            with self.assertRaisesRegex(probe.ProbeError, 'continuation'):
                probe.websocket_probe(self.config(server.port))


class ConfigurationTests(unittest.TestCase):
    def test_missing_required_endpoint_is_incomplete_and_no_network(self):
        with patch.object(probe.socket, 'socket') as sock:
            result = probe.run_suite({'network': {'websocket': [{'id': 'cn-v6', 'url': None, 'answer_family': 6}]}})
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['summary']['skip'], 1)
        sock.assert_not_called()

    def test_missing_dns_server_or_name_skips_without_network(self):
        with patch.object(probe.socket, 'socket') as sock:
            result = probe.run_suite({'dns': [
                {'id': 'missing-server', 'name': 'fixture.test'},
                {'id': 'missing-name', 'server': '127.0.0.1'},
                {'id': 'empty-endpoint', 'server': '', 'name': ''},
            ]})
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['summary'], {'pass': 0, 'fail': 0, 'skip': 3})
        sock.assert_not_called()

    def test_empty_configuration_is_not_green(self):
        self.assertEqual(probe.run_suite({})['status'], 'incomplete')

    def test_unknown_group_duplicate_ids_and_invalid_numeric_config(self):
        for value in ({'dnz': []}, {'http': [{'id': 'x'}, {'id': 'x'}]}):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                probe.run_suite(value)
        for timeout in (float('nan'), float('inf'), -1, True):
            result = probe.run_suite({'dns': [{'server': '127.0.0.1', 'name': 'fixture.test', 'timeout': timeout}]})
            self.assertEqual(result['status'], 'fail')

    def test_existing_evidence_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            config, output = Path(directory) / 'in.json', Path(directory) / 'out.json'
            config.write_text('{}')
            output.write_text('previous evidence')
            with patch('builtins.print'):
                self.assertEqual(probe.main(['--config', str(config), '--output', str(output)]), 1)
            self.assertEqual(output.read_text(), 'previous evidence')

    def test_non_string_qtype_is_structured_failure(self):
        result = probe.run_suite({'dns': [{'server': '127.0.0.1', 'name': 'fixture.test', 'qtype': 28}]})
        self.assertEqual(result['status'], 'fail')
        self.assertIn('qtype', result['results'][0]['reason'])

    def test_cli_incomplete_exit_two_and_malformed_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            config, output = Path(directory) / 'in.json', Path(directory) / 'out.json'
            config.write_text(json.dumps({'websocket': [{'id': 'cn-v6'}]}))
            with patch('builtins.print'):
                self.assertEqual(probe.main(['--config', str(config), '--output', str(output)]), 2)
            self.assertEqual(json.loads(output.read_text())['status'], 'incomplete')
            config.write_text('{broken')
            output = Path(directory) / 'malformed.json'
            with patch('builtins.print'):
                self.assertEqual(probe.main(['--config', str(config), '--output', str(output)]), 1)
            self.assertEqual(json.loads(output.read_text())['status'], 'fail')


if __name__ == '__main__':
    unittest.main()
