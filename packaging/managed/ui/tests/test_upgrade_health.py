"""Local resolver readiness: real Lua, mocked procd/procfs, no network or C build."""
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_control import Harness

SOURCE = (Path(__file__).parents[2] / "upgrade-health.lua").read_text()
EXE = "/usr/libexec/diversion-dns-c"


# Keep DNS octets inside Lua: lupa's default UTF-8 conversion must not turn an
# invalid wire response into an artificial Python decoding failure.
SOCKET_FIXTURE = r'''
local N=require('nixio')
NET={created=0,closed=0,received=0,sent=0,polls=0,reply='normal',fault='',elapsed=0,options={},connections={},packets={}}
local function u16(v)return string.char(math.floor(v/256),v%256)end
local function hex(s)return(s:gsub('.',function(c)return string.format('%02x',c:byte())end))end
local function checked(stage,kind)
 local fault=NET.fault
 if fault:find(':',1,true)then local protocol;protocol,fault=fault:match('^(.-):(.*)$');if protocol~=kind then return true end end
 if fault==stage..'_error'then error('fixture '..stage..' exception')end
 return fault~=stage
end
local function question_end(s)
 local pos=13
 while s:byte(pos)and s:byte(pos)~=0 do pos=pos+s:byte(pos)+1 end
 return pos+4
end
local function reply(query)
 if NET.reply=='timeout'then return nil,11,'timeout'end
 if NET.reply=='echo'then return query end
 local q=query:sub(13,question_end(query))
 local packet=query:sub(1,2)..u16(32768+(NET.rcode or 0))..u16(1)..string.rep('\0',6)..q
 local kind=NET.reply
 if kind=='short'then return packet:sub(1,11)end
 if kind=='question_short'then return packet:sub(1,-2)end
 if kind=='id'then return string.char((query:byte(1)+1)%256)..packet:sub(2)end
 if kind=='name'then return packet:sub(1,13)..string.char((packet:byte(14)+1)%128)..packet:sub(15)end
 if kind=='type'then return packet:sub(1,-5)..u16(28)..packet:sub(-2)end
 if kind=='class'then return packet:sub(1,-3)..u16(3)end
 if kind=='qd0'then return packet:sub(1,4)..u16(0)..packet:sub(7)end
 if kind=='qd2'then return packet:sub(1,4)..u16(2)..packet:sub(7)end
 if kind=='opcode'then return packet:sub(1,2)..u16(32768+2048)..packet:sub(5)end
 if kind=='tc'then return packet:sub(1,2)..u16(32768+512)..packet:sub(5)end
 if kind=='rr_missing'then return packet:sub(1,6)..u16(1)..packet:sub(9)end
 if kind=='rr_short'then return packet:sub(1,6)..u16(1)..packet:sub(9)..'\192\12\0\1'end
 if kind=='rdata_short'then return packet:sub(1,6)..u16(1)..packet:sub(9)..'\192\12\0\1\0\1\0\0\0\60\0\4\192\0'end
 if kind=='trailing'then return packet..'\0'end
 if kind=='valid_a'then return packet:sub(1,6)..u16(1)..packet:sub(9)..'\192\12\0\1\0\1\0\0\0\60\0\4\192\0\2\1'end
 if kind=='pointer_oob'then return packet:sub(1,6)..u16(1)..packet:sub(9)..'\255\255\0\1\0\1\0\0\0\60\0\4\192\0\2\1'end
 if kind=='pointer_loop'then local at=#packet;return packet:sub(1,6)..u16(1)..packet:sub(9)..u16(49152+at)..'\0\1\0\1\0\0\0\60\0\4\192\0\2\1'end
 if kind=='oversized'then return packet..string.rep('\0',65536)end
 return packet
end
N.const={EAGAIN=11,EWOULDBLOCK=11,EINPROGRESS=115,EALREADY=114,EINTR=4}
N.socket=function(family,kind)
 NET.family=family;NET.kind=kind
 if not checked('socket',kind)then return nil end
 NET.created=NET.created+1
 local sock={kind=kind,query='',wire='',offset=1}
 function sock:setsockopt(level,option,sec,usec)
  NET.options[#NET.options+1]={level,option,sec,usec}
  return checked('setsockopt',kind)
 end
 function sock:setblocking(value)NET.blocking=value;return checked('setblocking',kind)end
 function sock:connect(host,port)
  NET.connections[#NET.connections+1]={host,tostring(port)}
  if not checked('connect',kind)then return nil,5 end
  if NET.connect_pending and kind=='stream'then return nil,N.const.EINPROGRESS end
  return true
 end
 function sock:getsockopt(level,option)
  assert(level=='socket'and option=='error')
  if not checked('getsockopt',kind)then return nil end
  return NET.connect_errno or 0
 end
 function sock:send(packet)
  NET.sent=NET.sent+1
  if not checked('send',kind)then return nil,5 end
  if NET.fault=='shortsend'then return #packet-1 end
  if NET.send_again and not self.sent_again then self.sent_again=true;return nil,11 end
  local n=math.min(#packet,(kind=='stream'and NET.tcp_send_chunk)or NET.send_chunk or #packet)
  self.wire=self.wire..packet:sub(1,n)
  if kind=='dgram'then self.query=self.wire
  elseif #self.wire>=2 then
   local size=self.wire:byte(1)*256+self.wire:byte(2)
   if #self.wire>=size+2 then self.query=self.wire:sub(3,2+size)end
  end
  if self.query~=''then NET.packets[#NET.packets+1]=hex(self.query)end
  return n
 end
 function sock:recv(limit)
  NET.received=NET.received+1;NET.recv_limit=limit
  if not checked('recv',kind)then return nil,5 end
  if NET.recv_again and not self.received_again then self.received_again=true;return nil,11 end
  if kind=='dgram'then local data,code=reply(self.query);return data and data:sub(1,limit),code end
  if not self.response then
   local original=NET.reply;if NET.tcp_dns_reply then NET.reply=NET.tcp_dns_reply end
   local data,code=reply(self.query);NET.reply=original;if not data then return nil,code end
   self.response=u16(#data)..data
   if NET.tcp_reply=='prefix_short'then self.response=self.response:sub(1,1)end
   if NET.tcp_reply=='body_short'then self.response=self.response:sub(1,-2)end
   if NET.tcp_reply=='empty'then self.response=''end
   if NET.tcp_reply=='zero_length'then self.response='\0\0'end
  end
  local n=math.min(limit,NET.recv_chunk or limit)
  local data=self.response:sub(self.offset,self.offset+n-1);self.offset=self.offset+#data
  return data
 end
 function sock:close()NET.closed=NET.closed+1;return checked('close',kind)end
 return sock
end
N.poll_flags=function(value)
 if type(value)=='number'then return {['in']=value==1,out=value==4,hup=value==16,err=value==8,nval=value==32}end
 return value=='in'and 1 or 4
end
N.poll=function(fds,timeout)
 NET.polls=NET.polls+1;NET.poll_timeout=timeout
 local sock=fds[1].fd
 if not checked('poll',sock.kind)then return nil,5 end
 if NET.poll_again and not sock.polled_again then sock.polled_again=true;return nil,4 end
 if NET.reply=='timeout'or(NET.tcp_reply=='timeout'and sock.kind=='stream')then NET.elapsed=NET.elapsed+timeout/1000;return 0 end
 if fds[1].events==1 and not sock.delayed then NET.elapsed=NET.elapsed+(NET.delay or 0);sock.delayed=true end
 if fds[1].events==1 and sock.kind=='stream'then NET.elapsed=NET.elapsed+(NET.drip_delay or 0)end
 for _,fd in ipairs(fds)do fd.revents=NET.revents or fd.events end
 return 1
end
N.gettimeofday=function()return 1000+math.floor(NET.elapsed),math.floor((NET.elapsed%1)*1000000)end
'''


class UpgradeHealth(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.service = {"diversion-dns": {"instances": {"instance1": {
            "running": True, "pid": 321, "command": [EXE, "start", "-c", "/etc/demo/config.conf"]
        }}}}
        self.rc = 0
        self.commands = []
        self.links = {"/proc/321/exe": EXE, "/proc/321/fd/3": "socket:[1234]", "/proc/321/fd/4": "socket:[1235]"}
        self.h.files["/proc/321/stat"] = self.stat()
        self.h.files["/proc/net/udp"] = self.row("udp", "127.0.0.1", 15353, 1234)
        self.h.files["/proc/net/tcp"] = self.row("tcp", "127.0.0.1", 15353, 1235)
        g = self.h.lua.globals()
        g.PY_LINK = lambda path: self.links.get(path)
        g.PY_DIR = lambda path: self.h.to_lua([".", "..", "3", "4"] if path == "/proc/321/fd" else [])
        g.PY_POPEN = self.popen
        self.h.lua.execute("require('nixio.fs').readlink=function(p)return PY_LINK(p)end;io.popen=function(c)return PY_POPEN(c)end")
        self.h.lua.execute(SOCKET_FIXTURE)
        self.net = self.h.lua.globals().NET
        self.nonce_reads = self.nonce_closes = 0
        self.nonce_error = False
        self.h.files["/dev/urandom"] = "0123456789abcdef"
        self.h.lua.globals().PY_OPEN = self.open
        self.api = self.h.lua.execute(SOURCE)
        self.profile = self.h.to_lua({"dns_host": "127.0.0.1", "dns_port": 15353})

    def open(self, path, mode=None):
        if path == "/proc/uptime":
            return self.h.lua.table_from({"read": lambda *args: f"{1000 + self.net.elapsed:.3f} 0.0\n", "close": lambda *args: True})
        if path == "/dev/urandom":
            if path not in self.h.files:
                return None

            def read(*args):
                self.nonce_reads += 1
                if self.nonce_error:
                    raise OSError("fixture random read error")
                return self.h.files[path]

            def close(*args):
                self.nonce_closes += 1
                return True

            return self.h.lua.table_from({"read": read, "close": close})
        return self.h.open(path, mode)

    @staticmethod
    def stat(state="S", started="12345"):
        return "321 (diversion-dns-c) " + state + " " + "0 " * 18 + started + " 0"

    @staticmethod
    def row(protocol, address, port, inode, state=None, remote="00000000:0000"):
        octets = [int(n) for n in address.split(".")]
        if sys.byteorder == "little":
            octets.reverse()
        host = "".join(f"{n:02X}" for n in octets)
        state = state or ("0A" if protocol == "tcp" else "07")
        return ("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
                f"  0: {host}:{port:04X} {remote} {state} 00000000:00000000 00:00000000 00000000 0 0 {inode} 1 0\n")

    def popen(self, command):
        self.commands.append(command)
        return self.h.lua.table_from({
            "read": lambda *args: json.dumps(self.service) + f"\nUPGRADE_HEALTH_RC={self.rc}\n",
            "close": lambda *args: True,
        })

    def check(self):
        return self.api.check(self.profile)

    def test_ipv4_only_local_listener_passes_without_external_dns_command(self):
        self.assertEqual(self.check(), (True, None))
        self.assertEqual(len(self.commands), 1)
        self.assertTrue(self.commands[0].startswith("ubus -t 3 call service list "))
        self.assertNotIn("baidu", self.commands[0])

    def test_readiness_roundtrip_targets_only_profile_listener(self):
        self.assertEqual(self.check(), (True, None))
        self.assertEqual(self.net.created, 2, "both owned DNS transports must answer")
        self.assertEqual(self.net.closed, self.net.created)
        self.assertEqual(self.net.sent, 2)
        self.assertEqual(self.net.received, 3)
        for _, endpoint in self.net.connections.items():
            self.assertEqual(self.h.to_py(endpoint), ["127.0.0.1", "15353"])
        for _, encoded in self.net.packets.items():
            packet = bytes.fromhex(encoded)
            _, flags, qd, an, ns, ar = struct.unpack("!6H", packet[:12])
            self.assertEqual(flags & 0xF800, 0, "probe must be a standard DNS query")
            self.assertEqual((qd, an, ns, ar), (1, 0, 0, 0))
            at, labels = 12, []
            while packet[at]:
                size = packet[at]
                self.assertLessEqual(size, 63)
                labels.append(packet[at + 1:at + 1 + size].decode("ascii"))
                at += size + 1
            self.assertEqual(labels[-1], "invalid", "probe must use a reserved .invalid name")
            self.assertEqual(struct.unpack("!2H", packet[at + 1:]), (1, 1))

    def test_any_structurally_valid_dns_rcode_is_ready(self):
        for rcode in range(16):
            with self.subTest(rcode=rcode):
                self.net.rcode = rcode
                before = self.net.created
                self.assertEqual(self.check(), (True, None))
                self.assertGreater(self.net.created, before)
                self.assertEqual(self.net.closed, self.net.created)

    def test_valid_answer_does_not_require_public_resolution_success(self):
        self.net.reply = "valid_a"
        self.assertEqual(self.check(), (True, None))
        self.assertGreater(self.net.received, 0)

    def test_slow_upstream_servfail_is_still_dns_readiness(self):
        self.net.rcode = 2
        self.net.delay = 5.5
        self.assertEqual(self.check(), (True, None))
        self.assertEqual(self.net.created, 2)
        self.assertGreaterEqual(self.net.elapsed, 11)
        self.assertEqual(self.net.closed, 2)

    def test_udp_response_alone_cannot_hide_unresponsive_tcp(self):
        self.net.tcp_reply = "timeout"
        self.assertFalse(self.check()[0])
        self.assertEqual(self.net.created, 2)
        self.assertEqual(self.net.closed, 2)
        self.assertGreaterEqual(self.net.elapsed, 7.9)
        self.assertLessEqual(self.net.elapsed, 8.1)

    def test_tcp_partial_prefix_body_and_send_are_reassembled(self):
        self.net.tcp_send_chunk = 1
        self.net.recv_chunk = 1
        self.assertEqual(self.check(), (True, None))
        self.assertGreater(self.net.received, 10)
        self.assertGreater(self.net.sent, 10)
        self.assertEqual(self.net.closed, 2)

    def test_tcp_eof_short_frame_and_zero_length_fail(self):
        for response in ("empty", "prefix_short", "body_short", "zero_length"):
            with self.subTest(response=response):
                self.net.tcp_reply = response
                self.assertFalse(self.check()[0])
                self.assertEqual(self.net.closed, self.net.created)

    def test_tcp_bad_dns_is_rejected_after_valid_udp(self):
        for response in ("id", "name", "type", "class", "echo", "opcode", "tc", "rdata_short", "trailing"):
            with self.subTest(response=response):
                self.net.tcp_dns_reply = response
                before = self.net.created
                self.assertFalse(self.check()[0])
                self.assertEqual(self.net.created - before, 2)
                self.assertEqual(self.net.closed, self.net.created)

    def test_tcp_slow_drip_cannot_reset_per_transport_deadline(self):
        self.net.recv_chunk = 1
        self.net.drip_delay = 0.9
        self.assertFalse(self.check()[0])
        self.assertLess(self.net.elapsed, 9)
        self.assertEqual(self.net.closed, 2)

    def test_connect_in_progress_and_transient_io_errors_can_complete(self):
        self.net.connect_pending = True
        self.net.send_again = True
        self.net.recv_again = True
        self.net.poll_again = True
        self.assertEqual(self.check(), (True, None))
        self.assertEqual(self.net.closed, 2)

    def test_async_connect_error_fails_and_closes(self):
        self.net.connect_pending = True
        self.net.connect_errno = 111
        self.assertFalse(self.check()[0])
        self.assertEqual(self.net.closed, self.net.created)

    def test_poll_and_nonblocking_failures_close_socket(self):
        for fault in ("setblocking", "setblocking_error", "poll", "poll_error", "getsockopt", "getsockopt_error"):
            with self.subTest(fault=fault):
                self.net.fault = fault
                self.net.connect_pending = True
                self.assertFalse(self.check()[0], fault)
                self.assertEqual(self.net.closed, self.net.created)

    def test_poll_error_hangup_or_invalid_descriptor_never_reports_ready(self):
        for revents in (8, 16, 32):
            with self.subTest(revents=revents):
                self.net.revents = revents
                self.assertFalse(self.check()[0])
                self.assertEqual(self.net.closed, self.net.created)

    def test_timeout_is_not_repeated_for_each_procd_instance(self):
        instance = self.service["diversion-dns"]["instances"]["instance1"]
        self.service["diversion-dns"]["instances"] = {f"instance{i}": dict(instance) for i in range(16)}
        self.net.reply = "timeout"
        self.assertFalse(self.check()[0])
        self.assertEqual(self.net.created, 1)
        self.assertEqual(self.net.closed, 1)
        self.assertLessEqual(self.net.elapsed, 8.1)

    def test_socket_close_failure_or_exception_is_not_readiness(self):
        for fault in ("close", "close_error", "stream:close", "stream:close_error"):
            with self.subTest(fault=fault):
                self.net.fault = fault
                self.assertFalse(self.check()[0])
                self.assertEqual(self.net.closed, self.net.created)

    def test_nonce_handle_is_closed_on_success_and_read_error(self):
        self.assertEqual(self.check(), (True, None))
        self.assertEqual(self.nonce_reads, 2)
        self.assertEqual(self.nonce_closes, 2)
        self.nonce_error = True
        self.assertFalse(self.check()[0])
        self.assertEqual(self.nonce_reads, 3)
        self.assertEqual(self.nonce_closes, 3)
        self.assertEqual(self.net.created, 2)

    def test_missing_or_short_nonce_fails_before_opening_network_socket(self):
        del self.h.files["/dev/urandom"]
        self.assertFalse(self.check()[0])
        self.h.files["/dev/urandom"] = "short"
        self.assertFalse(self.check()[0])
        self.assertEqual(self.net.created, 0)
        self.assertEqual(self.nonce_closes, 1)

    def test_missing_monotonic_clock_fails_before_network(self):
        self.h.lua.globals().PY_OPEN = lambda path, mode=None: None if path == "/proc/uptime" else self.open(path, mode)
        self.assertFalse(self.check()[0])
        self.assertEqual(self.net.created, 0)

    def test_process_identity_rechecked_after_dns_roundtrip(self):
        def changed(path, mode=None):
            if path == "/proc/321/stat" and self.net.received:
                self.h.files[path] = self.stat(started="99999")
            return self.open(path, mode)

        self.h.lua.globals().PY_OPEN = changed
        self.assertFalse(self.check()[0])
        self.assertEqual(self.net.created, 2)
        self.assertEqual(self.net.closed, 2)

    def test_listener_ownership_rechecked_after_dns_roundtrip(self):
        self.h.lua.globals().PY_LINK = lambda path: "socket:[9999]" if path == "/proc/321/fd/3" and self.net.received else self.links.get(path)
        self.assertFalse(self.check()[0])
        self.assertEqual(self.net.created, 2)
        self.assertEqual(self.net.closed, 2)

    def test_dns_timeout_rejects_owned_but_unresponsive_listener(self):
        self.net.reply = "timeout"
        ok, error = self.check()
        self.assertFalse(ok)
        self.assertTrue(error)
        self.assertGreater(self.net.created, 0)
        self.assertEqual(self.net.closed, self.net.created)

    def test_unmatched_or_malformed_dns_response_fails_and_closes(self):
        for response in ("short", "question_short", "id", "name", "type", "class", "qd0", "qd2",
                         "echo", "opcode", "tc", "rr_missing", "rr_short", "rdata_short", "trailing",
                         "pointer_oob", "pointer_loop", "oversized"):
            with self.subTest(response=response):
                self.net.reply = response
                ok, error = self.check()
                self.assertFalse(ok, response)
                self.assertTrue(error)
                self.assertGreater(self.net.created, 0)
                self.assertEqual(self.net.closed, self.net.created)

    def test_socket_creation_failure_never_reports_ready(self):
        for fault in ("socket", "socket_error"):
            with self.subTest(fault=fault):
                self.net.fault = fault
                self.assertFalse(self.check()[0])
                self.assertEqual(self.net.closed, 0)

    def test_connect_send_receive_failures_always_close(self):
        for fault in ("connect", "connect_error", "send", "send_error", "shortsend", "recv", "recv_error"):
            with self.subTest(fault=fault):
                self.net.fault = fault
                self.assertFalse(self.check()[0], fault)
                self.assertGreater(self.net.created, 0)
                self.assertEqual(self.net.closed, self.net.created)

    def test_invalid_identity_does_not_send_probe_to_another_process(self):
        self.links["/proc/321/exe"] = "/usr/sbin/dnsmasq"
        self.assertFalse(self.check()[0])
        self.assertEqual(self.net.created, 0)

    def test_wildcard_socket_accepts_configured_ipv4(self):
        for protocol, inode in [("udp", 1234), ("tcp", 1235)]:
            self.h.files[f"/proc/net/{protocol}"] = self.row(protocol, "0.0.0.0", 15353, inode)
        self.assertTrue(self.check()[0])

    def test_wildcard_listener_always_probes_loopback(self):
        self.profile = self.h.to_lua({"dns_host": "198.51.100.2", "dns_port": 15353})
        for protocol, inode in [("udp", 1234), ("tcp", 1235)]:
            self.h.files[f"/proc/net/{protocol}"] = self.row(protocol, "0.0.0.0", 15353, inode)
        self.assertEqual(self.check(), (True, None))
        self.assertEqual(len(self.net.connections), 2)
        for _, endpoint in self.net.connections.items():
            self.assertEqual(self.h.to_py(endpoint), ["127.0.0.1", "15353"])

    def test_unregistered_or_stopped_service_fails(self):
        self.service["diversion-dns"]["instances"]["instance1"]["running"] = False
        self.assertFalse(self.check()[0])
        self.service = {}
        self.assertFalse(self.check()[0])

    def test_wrong_executable_or_procd_command_fails(self):
        self.links["/proc/321/exe"] = "/usr/sbin/dnsmasq"
        self.assertFalse(self.check()[0])
        self.links["/proc/321/exe"] = EXE
        self.service["diversion-dns"]["instances"]["instance1"]["command"][0] = "/usr/sbin/dnsmasq"
        self.assertFalse(self.check()[0])

    def test_old_deleted_executable_does_not_prove_new_program_ready(self):
        self.links["/proc/321/exe"] = EXE + " (deleted)"
        self.assertFalse(self.check()[0])

    def test_stale_missing_pid_fails(self):
        del self.h.files["/proc/321/stat"]
        self.assertFalse(self.check()[0])

    def test_stopped_zombie_or_reused_pid_fails(self):
        for state in ("T", "t", "Z", "X"):
            self.h.files["/proc/321/stat"] = self.stat(state)
            self.assertFalse(self.check()[0])
        self.h.files["/proc/321/stat"] = self.stat()
        reads = 0

        def changing_open(path, mode=None):
            nonlocal reads
            if path == "/proc/321/stat":
                reads += 1
                if reads == 2:
                    self.h.files[path] = self.stat(started="99999")
            return self.open(path, mode)

        self.h.lua.globals().PY_OPEN = changing_open
        self.assertFalse(self.check()[0])

    def test_another_process_socket_does_not_satisfy_listener(self):
        self.links["/proc/321/fd/3"] = "socket:[9876]"
        self.assertFalse(self.check()[0])

    def test_wrong_address_or_port_fails(self):
        for address, port in [("127.0.0.2", 15353), ("127.0.0.1", 53), ("198.51.100.1", 15353)]:
            self.h.files["/proc/net/udp"] = self.row("udp", address, port, 1234)
            self.assertFalse(self.check()[0])

    def test_both_protocols_required(self):
        for protocol in ("udp", "tcp"):
            original = self.h.files.pop(f"/proc/net/{protocol}")
            self.assertFalse(self.check()[0])
            self.h.files[f"/proc/net/{protocol}"] = original

    def test_tcp_connected_socket_is_not_a_listener(self):
        self.h.files["/proc/net/tcp"] = self.row("tcp", "127.0.0.1", 15353, 1235, state="01")
        self.assertFalse(self.check()[0])

    def test_udp_upstream_socket_is_not_a_listener(self):
        self.h.files["/proc/net/udp"] = self.row("udp", "127.0.0.1", 15353, 1234, remote="0100007F:0035")
        self.assertFalse(self.check()[0])

    def test_bad_or_failed_ubus_response_fails(self):
        self.rc = 1
        self.assertFalse(self.check()[0])
        self.rc = 0
        self.service["diversion-dns"]["instances"] = "invalid"
        self.assertFalse(self.check()[0])

    def test_invalid_profile_fails_without_shell_interpolation(self):
        for host, port in [("::1", 15353), ("127.0.0.1; touch /tmp/bad", 15353), ("127.00.0.1", 15353), ("127.0.0.1", 0), ("127.0.0.1", 65536), ("127.0.0.1", "15353")]:
            self.profile = self.h.to_lua({"dns_host": host, "dns_port": port})
            self.assertFalse(self.check()[0])
        self.assertEqual(self.commands, [])


if __name__ == "__main__":
    unittest.main()
