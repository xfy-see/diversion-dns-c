#!/usr/bin/env python3
"""Explicit-endpoint DNS, HTTP and WebSocket checks; Python standard library only.

No public service is contacted by default, no environment proxies are read and
hostnames are resolved only through the configured DNS server. DNS qtype and IP
transport family are deliberately separate. See CONFIG_EXAMPLE for the schema.
"""
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import tempfile
import time
from urllib.parse import urlsplit

CONFIG_EXAMPLE = {
    "dns": [{"id": "cn-a", "server": "127.0.0.1", "port": 15491,
             "transport": "udp", "family": 4, "name": "cn.test", "qtype": "A"}],
    "http": [{"id": "cn-page", "url": "http://cn.test/", "dns_server": "127.0.0.1",
              "dns_port": 15491, "answer_family": 4, "expected_status": [200]}],
    "websocket": [{"id": "cn-ws-v6", "url": None, "answer_family": 6,
                   "duration": 30, "ping_interval": 5}],
}
QTYPE = {"A": 1, "AAAA": 28}
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LIMITATIONS = [
    "A/AAAA record type is independent of DNS transport IPv4/IPv6.",
    "An HTTP or WebSocket check connects to the first matching DNS answer; it does not test every address.",
    "Successful connections alone do not prove tunnel egress or policy routing; collect router route/mark/counter evidence separately.",
    "WebSocket stability covers only the configured duration and endpoints. Missing endpoints are skipped.",
    "HTTP reads at most max_bytes; body_complete distinguishes full-body/trailer validation from a bounded prefix. Redirects are not followed.",
    "These are functional probes, not fixed-arrival QPS load tests.",
]


class ProbeError(ValueError):
    """A protocol response or explicit endpoint configuration is invalid."""


def _number(value, name, minimum=0.001, maximum=3600):
    if isinstance(value, bool):
        raise ProbeError(name + " must be a number")
    try:
        value = float(value)
    except (TypeError, ValueError) as exc:
        raise ProbeError(name + " must be a number") from exc
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ProbeError("%s must be within [%s, %s]" % (name, minimum, maximum))
    return value


def _integer(value, name, minimum, maximum):
    number = _number(value, name, minimum, maximum)
    if int(number) != number:
        raise ProbeError(name + " must be an integer")
    return int(number)


def _family(value):
    if value not in (4, 6) or isinstance(value, bool):
        raise ProbeError("IP family must be 4 or 6")
    return socket.AF_INET if value == 4 else socket.AF_INET6


def _endpoint(address, port, family):
    # A literal is required: avoid accidental use of the host's resolver/proxy.
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ProbeError("server/peer must be a literal IP address") from exc
    if parsed.version != family:
        raise ProbeError("address and requested transport family disagree")
    _family(family)
    port = _integer(port, "port", 1, 65535)
    return (str(parsed), port) if family == 4 else (str(parsed), port, 0, 0)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("probe deadline exceeded")
    return remaining


class Wire:
    """Buffer partial TCP reads, preserving bytes after HTTP headers."""
    def __init__(self, sock):
        self.sock = sock
        self.buffer = bytearray()
        self.consumed = 0

    def read(self, count, deadline):
        while len(self.buffer) < count:
            self.sock.settimeout(_remaining(deadline))
            block = self.sock.recv(min(65536, max(count - len(self.buffer), 4096)))
            if not block:
                raise ProbeError("unexpected EOF in frame")
            self.buffer.extend(block)
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        self.consumed += count
        return result

    def headers(self, deadline, maximum=16384):
        while True:
            position = self.buffer.find(b"\r\n\r\n")
            if position >= 0:
                if position + 4 > maximum:
                    raise ProbeError("HTTP header exceeds limit")
                return self.read(position + 4, deadline)
            if len(self.buffer) >= maximum:
                raise ProbeError("HTTP header exceeds limit")
            self.sock.settimeout(_remaining(deadline))
            block = self.sock.recv(min(4096, maximum - len(self.buffer)))
            if not block:
                raise ProbeError("unexpected EOF in HTTP headers")
            self.buffer.extend(block)


def _dns_name(name):
    if not isinstance(name, str) or not name.rstrip("."):
        raise ProbeError("DNS name must be nonempty")
    labels = name.rstrip(".").split(".")
    try:
        encoded = [label.encode("idna") for label in labels]
    except UnicodeError as exc:
        raise ProbeError("invalid DNS name") from exc
    if any(not label or len(label) > 63 for label in encoded):
        raise ProbeError("invalid DNS label length")
    wire = b"".join(bytes([len(label)]) + label for label in encoded) + b"\0"
    if len(wire) > 255:
        raise ProbeError("DNS name exceeds 255 octets")
    return b".".join(encoded).decode("ascii").lower(), wire


def _read_name(packet, offset):
    labels, visited, end = [], set(), None
    size = 0
    while True:
        if offset in visited or offset >= len(packet):
            raise ProbeError("invalid DNS compression pointer")
        visited.add(offset)
        count = packet[offset]
        if count & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ProbeError("truncated DNS compression pointer")
            if end is None:
                end = offset + 2
            offset = ((count & 63) << 8) | packet[offset + 1]
            continue
        if count & 0xC0:
            raise ProbeError("invalid DNS label encoding")
        offset += 1
        if count == 0:
            return b".".join(labels).decode("ascii").lower(), end or offset
        if offset + count > len(packet):
            raise ProbeError("truncated DNS name")
        size += count + 1
        if size >= 255:
            raise ProbeError("expanded DNS name exceeds 255 octets")
        labels.append(packet[offset:offset + count])
        offset += count


def parse_dns(packet, query_id, name, qtype, expected_rcode=0, require_address=True):
    if len(packet) < 12:
        raise ProbeError("short DNS header")
    reply_id, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
    if reply_id != query_id:
        raise ProbeError("DNS transaction ID mismatch")
    if not flags & 0x8000 or flags & 0x7800:
        raise ProbeError("DNS response QR/opcode mismatch")
    if flags & 0x0200:
        raise ProbeError("truncated DNS response (TC); use a separate TCP probe")
    rcode = flags & 15
    if rcode != expected_rcode:
        raise ProbeError("unexpected DNS rcode %s (expected %s)" % (rcode, expected_rcode))
    if qd != 1:
        raise ProbeError("DNS question count must be one")
    question, offset = _read_name(packet, 12)
    if offset + 4 > len(packet):
        raise ProbeError("truncated DNS question")
    rtype, rclass = struct.unpack("!HH", packet[offset:offset + 4])
    offset += 4
    if (question, rtype, rclass) != (name.lower().rstrip("."), QTYPE[qtype], 1):
        raise ProbeError("DNS question mismatch")
    addresses, cnames, records = [], {}, []
    for index in range(an + ns + ar):
        owner, offset = _read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ProbeError("truncated DNS resource record")
        rtype, rclass, ttl, length = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        end = offset + length
        if end > len(packet):
            raise ProbeError("truncated DNS resource data")
        if index < an and rclass == 1:
            if rtype == 5:
                cname, used = _read_name(packet, offset)
                if used != end:
                    raise ProbeError("invalid CNAME resource length")
                cnames[owner] = cname
            elif rtype in (1, 28):
                expected_length = 4 if rtype == 1 else 16
                if length != expected_length:
                    raise ProbeError("invalid address resource length")
                records.append((owner, rtype, str(ipaddress.ip_address(packet[offset:end])), ttl))
        offset = end
    if offset != len(packet):
        raise ProbeError("trailing bytes after DNS records")
    owners, owner = set(), question
    while owner not in owners:
        owners.add(owner)
        if owner not in cnames:
            break
        owner = cnames[owner]
    else:
        raise ProbeError("CNAME loop")
    for owner, rtype, address, ttl in records:
        if owner in owners and rtype == QTYPE[qtype]:
            addresses.append({"address": address, "ttl": ttl, "owner": owner})
    if require_address and rcode == 0 and not addresses:
        raise ProbeError("DNS NOERROR answer contains no matching A/AAAA address")
    return {"rcode": rcode, "addresses": addresses, "flags": flags,
            "answer_count": an, "response_bytes": len(packet)}


def dns_query(item):
    family = item.get("family", 4)
    endpoint = _endpoint(item["server"], item.get("port", 53), family)
    timeout = _number(item.get("timeout", 3), "timeout", maximum=60)
    transport = item.get("transport", "udp")
    if transport not in ("udp", "tcp"):
        raise ProbeError("DNS transport must be udp or tcp")
    qtype = item.get("qtype", "A")
    if not isinstance(qtype, str):
        raise ProbeError("DNS qtype must be A or AAAA")
    qtype = qtype.upper()
    if qtype not in QTYPE:
        raise ProbeError("DNS qtype must be A or AAAA")
    name, question = _dns_name(item["name"])
    query_id = secrets.randbelow(65536)
    query = struct.pack("!6H", query_id, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", QTYPE[qtype], 1)
    start = time.monotonic()
    deadline = start + timeout
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    with socket.socket(_family(family), kind) as sock:
        sock.settimeout(_remaining(deadline))
        sock.connect(endpoint)
        sock.settimeout(_remaining(deadline))
        sock.sendall(query if transport == "udp" else struct.pack("!H", len(query)) + query)
        if transport == "udp":
            sock.settimeout(_remaining(deadline))
            packet = sock.recv(65536)
        else:
            wire = Wire(sock)
            length = struct.unpack("!H", wire.read(2, deadline))[0]
            if length < 12:
                raise ProbeError("short DNS TCP frame")
            packet = wire.read(length, deadline)
        local = sock.getsockname()
    result = parse_dns(packet, query_id, name, qtype,
                       _integer(item.get("expected_rcode", 0), "expected_rcode", 0, 15),
                       item.get("require_address", True))
    if "expect_addresses" in item:
        expected = {str(ipaddress.ip_address(value)) for value in item["expect_addresses"]}
        actual = {answer["address"] for answer in result["addresses"]}
        if actual != expected:
            raise ProbeError("DNS address set mismatch: got %s expected %s" % (sorted(actual), sorted(expected)))
    result.update({"server": endpoint[0], "port": endpoint[1], "transport": transport,
                   "transport_family": family, "family": family, "answer_family": 4 if qtype == "A" else 6, "qtype": qtype, "name": name, "query_id": query_id,
                   "local_address": local[0], "local_port": local[1],
                   "elapsed_ms": (time.monotonic() - start) * 1000})
    return result


def _url(item, schemes):
    url = item.get("url")
    if not isinstance(url, str) or any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ProbeError("URL must be a string without control characters")
    parsed = urlsplit(url)
    if parsed.scheme not in schemes or not parsed.hostname:
        raise ProbeError("URL must use " + "/".join(schemes) + " and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ProbeError("credentials in URL are not supported")
    if parsed.fragment:
        raise ProbeError("URL fragments are not sent over the network; remove the fragment")
    hostname = parsed.hostname.encode("idna").decode("ascii")
    port = parsed.port or (443 if parsed.scheme in ("https", "wss") else 80)
    path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    try:
        path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProbeError("URL path/query must be percent-encoded") from exc
    host = "[" + hostname + "]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme in ("https", "wss") else 80
    if port != default_port:
        host += ":" + str(port)
    return parsed.scheme, hostname, port, path, host


def _resolve(item, hostname):
    family = item.get("answer_family", 4)
    _family(family)
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if literal.version != family:
            raise ProbeError("URL address does not match answer_family")
        return str(literal), {"source": "URL literal", "addresses": [str(literal)]}
    if not item.get("dns_server"):
        raise ProbeError("dns_server is required for hostname URLs; system DNS is never used")
    result = dns_query({"server": item["dns_server"], "port": item.get("dns_port", 53),
                        "transport": item.get("dns_transport", "udp"), "family": item.get("dns_family", 4),
                        "name": hostname, "qtype": "A" if family == 4 else "AAAA",
                        "timeout": item.get("timeout", 5)})
    return result["addresses"][0]["address"], result


def _connect(item, address, port, hostname, secure, deadline):
    sock = socket.socket(_family(item.get("answer_family", 4)), socket.SOCK_STREAM)
    try:
        sock.settimeout(_remaining(deadline))
        sock.connect(_endpoint(address, port, item.get("answer_family", 4)))
        if secure:
            context = ssl.create_default_context(cafile=item.get("ca_file"))
            sock.settimeout(_remaining(deadline))
            sock = context.wrap_socket(sock, server_hostname=hostname)
        return sock
    except BaseException:
        sock.close()
        raise


def http_probe(item):
    scheme, hostname, port, path, host = _url(item, ("http", "https"))
    timeout = _number(item.get("timeout", 5), "timeout", maximum=60)
    max_bytes = _integer(item.get("max_bytes", 65536), "max_bytes", 1, 1048576)
    statuses = item.get("expected_status", [200])
    if not isinstance(statuses, list) or not statuses:
        raise ProbeError("expected_status must be a nonempty list")
    statuses = [_integer(value, "HTTP status", 100, 599) for value in statuses]
    start = time.monotonic()
    address, dns = _resolve(item, hostname)
    connected = time.monotonic()
    deadline = connected + timeout
    sock = _connect(item, address, port, hostname, scheme == "https", deadline)
    connection = http.client.HTTPConnection(hostname, port, timeout=timeout)
    connection.sock = sock
    try:
        connect_ms = (time.monotonic() - connected) * 1000
        request = "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: diversion-dns-suite/1\r\nAccept: */*\r\nConnection: close\r\n\r\n" % (path, host)
        sock.settimeout(_remaining(deadline))
        sock.sendall(request.encode("ascii"))
        # HTTPResponse parses status and headers; bounded body/chunk/trailer
        # framing is checked below under the same absolute deadline.
        wire = Wire(sock)
        headers = wire.headers(deadline)
        first_byte_ms = (time.monotonic() - connected) * 1000
        class BufferedSocket:
            def makefile(self, mode):
                import io
                return io.BytesIO(headers)
        response = http.client.HTTPResponse(BufferedSocket())
        response.begin()
        status = response.status
        content_length = response.getheader("Content-Length")
        # Reading the whole response is not required for availability; sample
        # a bounded prefix and keep its digest. Framing is validated explicitly.
        body = bytearray()
        no_body = status in (204, 304) or 100 <= status < 200
        chunked = response.chunked and not no_body
        body_complete = no_body
        if no_body:
            remaining = 0
        elif content_length is not None:
            remaining = _integer(content_length, "Content-Length", 0, 2 ** 63 - 1)
        else:
            remaining = None
        if chunked:
            while len(body) < max_bytes:
                line = bytearray()
                while not line.endswith(b"\r\n"):
                    if len(line) >= 8192:
                        raise ProbeError("HTTP chunk header exceeds limit")
                    line.extend(wire.read(1, deadline))
                try:
                    length = int(bytes(line).split(b";", 1)[0].strip(), 16)
                except ValueError as exc:
                    raise ProbeError("invalid HTTP chunk size") from exc
                if length < 0:
                    raise ProbeError("negative HTTP chunk size")
                if length == 0:
                    trailer_bytes = 0
                    while True:
                        trailer = bytearray()
                        while not trailer.endswith(b"\r\n"):
                            trailer_bytes += 1
                            if trailer_bytes > 16384:
                                raise ProbeError("HTTP trailers exceed limit")
                            trailer.extend(wire.read(1, deadline))
                        if trailer == b"\r\n":
                            break
                        if b":" not in trailer or trailer[:1].isspace():
                            raise ProbeError("invalid HTTP trailer")
                    body_complete = True
                    break
                take = min(length, max_bytes - len(body))
                body.extend(wire.read(take, deadline))
                if take < length or len(body) >= max_bytes:
                    break
                if wire.read(2, deadline) != b"\r\n":
                    raise ProbeError("invalid HTTP chunk terminator")
        elif remaining is not None:
            body.extend(wire.read(min(remaining, max_bytes), deadline))
            body_complete = remaining <= max_bytes
        else:
            while len(body) < max_bytes:
                if wire.buffer:
                    take = min(len(wire.buffer), max_bytes - len(body))
                    body.extend(wire.read(take, deadline))
                else:
                    sock.settimeout(_remaining(deadline))
                    block = sock.recv(min(4096, max_bytes - len(body)))
                    if not block:
                        body_complete = True
                        break
                    body.extend(block)
        if status not in statuses:
            raise ProbeError("unexpected HTTP status %s (expected %s)" % (status, statuses))
        return {"url": item["url"], "peer": address, "port": port, "answer_family": item.get("answer_family", 4),
                "dns_transport_family": item.get("dns_family", 4), "host_header": host, "tls_verified": scheme == "https", "system_proxy_used": False,
                "dns": dns, "http_status": status, "body_sample_bytes": len(body),
                "body_sample_sha256": hashlib.sha256(body).hexdigest(),
                "body_limit_reached": len(body) == max_bytes, "body_complete": body_complete,
                "connect_tls_ms": connect_ms, "headers_ms": first_byte_ms,
                "elapsed_ms": (time.monotonic() - start) * 1000,
                "redirect_followed": False}
    finally:
        connection.close()


def _send_frame(sock, opcode, payload, deadline):
    if len(payload) > 125:
        raise ProbeError("client control frame exceeds 125 bytes")
    mask = secrets.token_bytes(4)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    sock.settimeout(_remaining(deadline))
    sock.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + masked)


def _read_frame(wire, deadline):
    first, second = wire.read(2, deadline)
    if first & 0x70:
        raise ProbeError("unexpected WebSocket RSV bits")
    opcode, final = first & 15, bool(first & 0x80)
    if opcode not in (0, 1, 2, 8, 9, 10):
        raise ProbeError("invalid WebSocket opcode")
    if second & 0x80:
        raise ProbeError("server WebSocket frame must not be masked")
    length = second & 127
    if length == 126:
        length = struct.unpack("!H", wire.read(2, deadline))[0]
        if length < 126:
            raise ProbeError("nonminimal WebSocket frame length")
    elif length == 127:
        length = struct.unpack("!Q", wire.read(8, deadline))[0]
        if length < 65536 or length >= 2 ** 63:
            raise ProbeError("invalid WebSocket 64-bit frame length")
    if opcode >= 8 and (not final or length > 125):
        raise ProbeError("invalid WebSocket control frame")
    if length > 1048576:
        raise ProbeError("WebSocket frame exceeds 1 MiB probe limit")
    if opcode == 8 and length == 1:
        raise ProbeError("invalid WebSocket close payload")
    return opcode, final, wire.read(length, deadline)


def websocket_probe(item):
    scheme, hostname, port, path, host = _url(item, ("ws", "wss"))
    duration = _number(item.get("duration", 30), "duration", maximum=43200)
    interval = _number(item.get("ping_interval", 5), "ping_interval", maximum=3600)
    timeout = _number(item.get("timeout", 5), "timeout", maximum=60)
    if math.ceil(duration / interval) > 100000:
        raise ProbeError("WebSocket ping schedule exceeds 100000-sample evidence limit")
    start = time.monotonic()
    address, dns = _resolve(item, hostname)
    deadline = time.monotonic() + timeout
    sock = _connect(item, address, port, hostname, scheme == "wss", deadline)
    samples, events = [], []
    try:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n") % (path, host, key)
        sock.settimeout(_remaining(deadline))
        sock.sendall(request.encode("ascii"))
        wire = Wire(sock)
        lines = wire.headers(deadline).decode("iso-8859-1").split("\r\n")
        status = lines[0].split(" ", 2)
        if len(status) < 2 or status[0] != "HTTP/1.1" or status[1] != "101":
            raise ProbeError("WebSocket handshake did not return HTTP/1.1 101")
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line or line[0].isspace():
                raise ProbeError("invalid WebSocket handshake header")
            name, value = line.split(":", 1)
            name, value = name.lower(), value.strip()
            if name in headers:
                headers[name] += "," + value
            else:
                headers[name] = value
        expected = base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise ProbeError("Sec-WebSocket-Accept mismatch")
        if headers.get("upgrade", "").lower() != "websocket" or "upgrade" not in [value.strip().lower() for value in headers.get("connection", "").split(",")]:
            raise ProbeError("invalid WebSocket Upgrade/Connection header")
        if headers.get("sec-websocket-extensions") or headers.get("sec-websocket-protocol"):
            raise ProbeError("server selected unrequested WebSocket extension/subprotocol")
        ready = time.monotonic()
        end = ready + duration
        next_ping, pending, sent_at, fragmented = ready, None, None, False
        data_frames = server_pings = unsolicited_pongs = 0
        while True:
            now = time.monotonic()
            if now >= end and pending is None:
                break
            if pending is None and now >= next_ping and now < end:
                pending = secrets.token_bytes(12)
                sent_at = now
                _send_frame(sock, 9, pending, now + timeout)
                events.append({"event": "ping_sent", "offset_ms": (now - ready) * 1000,
                               "payload_hex": pending.hex()})
                next_ping = now + interval
            # An outstanding final ping must receive its matching pong, even
            # if its timeout extends just beyond the configured duration.
            read_deadline = sent_at + timeout if pending is not None else min(next_ping, end)
            if pending is not None and now >= read_deadline:
                raise ProbeError("WebSocket matching pong timeout")
            consumed_before = wire.consumed
            try:
                opcode, final, payload = _read_frame(wire, read_deadline)
            except (socket.timeout, TimeoutError):
                if pending is not None:
                    raise ProbeError("WebSocket matching pong timeout")
                # A timeout after a partial frame is fatal: otherwise the next
                # iteration could reinterpret remaining payload as a header.
                if wire.buffer or wire.consumed != consumed_before:
                    raise ProbeError("WebSocket partial frame timed out")
                continue
            now = time.monotonic()
            if opcode == 10:
                if pending is not None and payload == pending:
                    samples.append({"sent_offset_ms": (sent_at - ready) * 1000,
                                    "received_offset_ms": (now - ready) * 1000,
                                    "rtt_ms": (now - sent_at) * 1000,
                                    "payload_hex": payload.hex()})
                    pending = None
                else:
                    unsolicited_pongs += 1
            elif opcode == 9:
                server_pings += 1
                _send_frame(sock, 10, payload, now + timeout)
            elif opcode == 8:
                events.append({"event": "server_close", "offset_ms": (now - ready) * 1000,
                               "payload_hex": payload.hex()})
                raise ProbeError("WebSocket closed before duration completed")
            else:
                if opcode == 0:
                    if not fragmented:
                        raise ProbeError("unexpected WebSocket continuation frame")
                    fragmented = not final
                else:
                    if fragmented:
                        raise ProbeError("new WebSocket data frame during fragmented message")
                    fragmented = not final
                data_frames += 1
        if fragmented:
            raise ProbeError("WebSocket ended with incomplete fragmented message")
        close_start = time.monotonic()
        _send_frame(sock, 8, struct.pack("!H", 1000), close_start + timeout)
        close_ack = False
        # Graceful close is an extra recorded observation. A peer not closing
        # back does not erase a completed stability interval.
        try:
            opcode, _, payload = _read_frame(wire, close_start + min(timeout, 1))
            close_ack = opcode == 8
        except (OSError, ProbeError, TimeoutError):
            pass
        return {"url": item["url"], "peer": address, "port": port, "answer_family": item.get("answer_family", 4),
                "dns_transport_family": item.get("dns_family", 4), "host_header": host, "tls_verified": scheme == "wss", "system_proxy_used": False,
                "dns": dns, "handshake_ms": (ready - start) * 1000,
                "requested_duration_seconds": duration, "observed_duration_seconds": close_start - ready,
                "ping_count": len(samples), "pong_samples": samples, "events": events,
                "data_frames": data_frames, "server_pings": server_pings,
                "unsolicited_pongs": unsolicited_pongs, "close_acknowledged": close_ack,
                "elapsed_ms": (time.monotonic() - start) * 1000}
    except Exception as exc:
        # The top-level runner retains partial evidence for failed long runs.
        exc.probe_evidence = {"peer": address, "dns": dns, "pong_samples": samples,
                              "events": events, "elapsed_ms": (time.monotonic() - start) * 1000}
        raise
    finally:
        sock.close()


def run_suite(config):
    if not isinstance(config, dict):
        raise ProbeError("configuration root must be an object")
    if "network" in config:
        config = config["network"]
        if not isinstance(config, dict):
            raise ProbeError("network configuration must be an object")
    unknown = set(config) - {"dns", "http", "websocket", "metadata"}
    if unknown:
        raise ProbeError("unknown configuration groups: " + ", ".join(sorted(unknown)))
    results, ids = [], set()
    for group, function in (("dns", dns_query), ("http", http_probe), ("websocket", websocket_probe)):
        entries = config.get(group, [])
        if not isinstance(entries, list):
            raise ProbeError(group + " must be a list")
        for index, item in enumerate(entries):
            if not isinstance(item, dict):
                raise ProbeError("each probe must be an object")
            probe_id = item.get("id", "%s-%s" % (group, index + 1))
            if not isinstance(probe_id, str) or not probe_id or probe_id in ids:
                raise ProbeError("probe IDs must be nonempty unique strings")
            ids.add(probe_id)
            required = item.get("required", True)
            if not isinstance(required, bool):
                raise ProbeError("required must be true or false")
            result = {"id": probe_id, "kind": group, "required": required,
                      "started_at_unix": time.time()}
            if group == "dns":
                result.update({"family": item.get("family", 4),
                               "answer_family": {"A": 4, "AAAA": 6}.get(str(item.get("qtype", "A")).upper()),
                               "name": item.get("name"), "server": item.get("server"),
                               "transport": item.get("transport", "udp")})
            else:
                result.update({"family": item.get("answer_family", 4),
                               "answer_family": item.get("answer_family", 4),
                               "dns_transport_family": item.get("dns_family", 4)})
            started = time.monotonic()
            if group == "dns" and (not item.get("server") or not item.get("name")):
                result.update({"status": "skip", "reason": "No explicit DNS server/name configured; endpoint coverage unavailable."})
            elif group in ("http", "websocket") and not item.get("url"):
                result.update({"status": "skip", "reason": "No explicit URL configured; endpoint coverage unavailable."})
            else:
                try:
                    result.update({"status": "pass", "detail": function(item)})
                except (OSError, ValueError, KeyError, TypeError, UnicodeError, http.client.HTTPException) as exc:
                    result.update({"status": "fail", "error_type": type(exc).__name__, "reason": str(exc)})
                    if hasattr(exc, "probe_evidence"):
                        result["detail"] = exc.probe_evidence
            result["elapsed_ms"] = (time.monotonic() - started) * 1000
            results.append(result)
    summary = {status: sum(item["status"] == status for item in results) for status in ("pass", "fail", "skip")}
    incomplete = not summary["pass"] or any(item["status"] == "skip" and item["required"] for item in results)
    overall = "fail" if summary["fail"] else ("incomplete" if incomplete else "pass")
    return {"schema_version": 1, "status": overall, "summary": summary, "results": results,
            "limitations": LIMITATIONS, "metadata": config.get("metadata", {})}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Explicit endpoint JSON configuration")
    parser.add_argument("--output", required=True, type=Path, help="Raw structured JSON result")
    args = parser.parse_args(argv)
    if args.output.exists():
        print(json.dumps({"status": "fail", "reason": "Refusing to overwrite existing evidence", "output": str(args.output)}))
        return 1
    try:
        result = run_suite(json.loads(args.config.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError) as exc:
        result = {"schema_version": 1, "status": "fail", "configuration_error": str(exc), "results": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=args.output.parent,
                                         prefix=".network-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        # link is atomic and refuses an existing destination, including a
        # concurrent writer. Temp and destination reside on the same filesystem.
        os.link(temporary, args.output)
    except OSError as exc:
        print(json.dumps({"status": "fail", "reason": str(exc), "output": str(args.output)}))
        return 1
    finally:
        if temporary is not None:
            temporary.unlink()
    print(json.dumps({"status": result["status"], "summary": result.get("summary", {}), "output": str(args.output)}))
    return 1 if result["status"] == "fail" else (2 if result["status"] in ("incomplete", "skip") else 0)


if __name__ == "__main__":
    raise SystemExit(main())
