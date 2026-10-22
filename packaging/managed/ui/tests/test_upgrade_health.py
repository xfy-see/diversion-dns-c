"""Local resolver readiness: real Lua, mocked procd/procfs, no network or C build."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from test_control import Harness

SOURCE = (Path(__file__).parents[2] / "upgrade-health.lua").read_text()
EXE = "/usr/libexec/diversion-dns-c"


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
        self.api = self.h.lua.execute(SOURCE)
        self.profile = self.h.to_lua({"dns_host": "127.0.0.1", "dns_port": 15353})

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

    def test_ipv4_only_local_listener_passes_without_external_dns(self):
        self.assertEqual(self.check(), (True, None))
        self.assertEqual(len(self.commands), 1)
        self.assertTrue(self.commands[0].startswith("ubus -t 3 call service list "))
        self.assertNotIn("baidu", self.commands[0])

    def test_wildcard_socket_accepts_configured_ipv4(self):
        for protocol, inode in [("udp", 1234), ("tcp", 1235)]:
            self.h.files[f"/proc/net/{protocol}"] = self.row(protocol, "0.0.0.0", 15353, inode)
        self.assertTrue(self.check()[0])

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
            return self.h.open(path, mode)

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
