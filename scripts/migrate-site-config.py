#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Strict, offline migration of the historical site-only YAML graph.

PyYAML is a dependency of this optional tool, never of the DNS runtime. This is
not a general YAML-to-conf translator: the complete graph must be proved before
any output is created. No rules, sockets, interfaces or nftables are accessed.
"""
import argparse
import ipaddress
from pathlib import Path
import re
import sys

try:
    import yaml
except ImportError:
    yaml = None

MAX_BYTES = 1024 * 1024
MAX_ITEMS = 64
UINT32_MAX = 4294967295
ASCII_WS = " \t\r\n\v\f"
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,126}\Z")
TAG = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,126}\Z")


class MigrationError(ValueError):
    pass


class MarkedMap(dict):
    pass


class MarkedList(list):
    pass


class MarkedString(str):
    pass


class Converter:
    def __init__(self, source):
        self.source = source
        self.lines = []
        self.plugins = {}
        self.used = set()

    def fail(self, value, message):
        raise MigrationError(f"{self.source}:{getattr(value, 'line', 1)}: {message}")

    def read(self, text):
        if yaml is None:
            self.fail(None, "migration requires optional PyYAML (the DNS runtime does not)")
        try:
            encoded_size = len(text.encode("utf-8"))
        except UnicodeError:
            self.fail(None, "YAML input must be valid UTF-8")
        if encoded_size > MAX_BYTES:
            self.fail(None, "YAML input exceeds 1 MiB")
        try:
            # Reject before composition: in particular an alias can never expand
            # into a second object, conceal a duplicate, or make a recursive graph.
            for token in yaml.scan(text):
                if isinstance(token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken,
                                      yaml.tokens.TagToken, yaml.tokens.DirectiveToken)):
                    raise MigrationError(f"{self.source}:{token.start_mark.line + 1}: "
                                         "anchors, aliases, explicit tags and directives are unsupported")
            root = yaml.compose(text, Loader=yaml.BaseLoader)
            count = 0

            def convert(node, depth=0):
                nonlocal count
                count += 1
                if depth > 40 or count > 10000:
                    self.fail(None, "YAML structure exceeds migration limits")
                if isinstance(node, yaml.ScalarNode):
                    value = MarkedString(node.value)
                elif isinstance(node, yaml.SequenceNode):
                    value = MarkedList(convert(item, depth + 1) for item in node.value)
                elif isinstance(node, yaml.MappingNode):
                    value = MarkedMap()
                    for key_node, item in node.value:
                        key = convert(key_node, depth + 1)
                        if not isinstance(key, str) or not key:
                            self.fail(key, "mapping keys must be nonempty scalar strings")
                        if key in value:
                            self.fail(key, f"duplicate mapping key: {key}")
                        if key == "<<":
                            self.fail(key, "YAML merge keys are unsupported")
                        value[key] = convert(item, depth + 1)
                else:
                    self.fail(None, "expected exactly one YAML mapping document")
                value.line = node.start_mark.line + 1
                return value

            return convert(root)
        except yaml.YAMLError as error:
            mark = getattr(error, "problem_mark", None)
            line = mark.line + 1 if mark else 1
            raise MigrationError(f"{self.source}:{line}: invalid YAML: {error}") from error
        except RecursionError as error:
            self.fail(None, "YAML structure is too deeply nested")

    def mapping(self, value, allowed, required=()):
        if not isinstance(value, dict):
            self.fail(value, "expected a mapping")
        extra = set(value) - set(allowed)
        missing = set(required) - set(value)
        if extra:
            self.fail(value, f"unsupported field(s): {', '.join(sorted(extra))}")
        if missing:
            self.fail(value, f"missing field(s): {', '.join(sorted(missing))}")
        return value

    def sequence(self, value, minimum=1, maximum=MAX_ITEMS):
        if not isinstance(value, list) or not minimum <= len(value) <= maximum:
            self.fail(value, f"expected a list with {minimum}..{maximum} entries")
        return value

    def string(self, value):
        if not isinstance(value, str) or not value:
            self.fail(value, "expected a nonempty scalar string")
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            self.fail(value, "surrogate codepoints cannot be encoded as UTF-8")
        if value != value.strip(ASCII_WS) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            self.fail(value, "value has whitespace/control bytes that cannot be preserved literally")
        return value

    def integer(self, value, minimum, maximum):
        if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9]+|0[xX][0-9a-fA-F]+)", value):
            self.fail(value, "expected an unsigned decimal or hexadecimal integer")
        hexadecimal = value[:2].lower() == "0x"
        digits = (value[2:] if hexadecimal else value).lstrip("0") or "0"
        # Bound conversion before int(): Python limits long decimal strings and
        # the legacy YAML can contain arbitrarily many leading zeroes.
        limit = format(maximum, "x") if hexadecimal else str(maximum)
        if len(digits) > len(limit):
            self.fail(value, f"integer must be in {minimum}..{maximum}")
        number = int(digits, 16 if hexadecimal else 10)
        if not minimum <= number <= maximum:
            self.fail(value, f"integer must be in {minimum}..{maximum}")
        return number

    def emit(self, key, value):
        value = str(value)
        self.string(value)
        line = f"{key}={value}"
        if len(line.encode("utf-8")) > 4096:
            self.fail(None, f"generated {key} line exceeds 4096 bytes")
        self.lines.append(line)

    def address(self, value, upstream=False, seen=None):
        value = self.string(value)
        original = value
        if upstream:
            if value.startswith(("udp://", "tcp://")):
                value = value[6:]
            elif "://" in value:
                self.fail(original, "only numeric UDP/TCP upstreams are supported")
        if not value or len(value.encode("utf-8")) >= 256:
            self.fail(original, "invalid or overlong numeric socket address")
        port = None
        if value.startswith("["):
            match = re.fullmatch(r"\[([^\]]+)\](?::([0-9]+))?", value)
            if not match:
                self.fail(original, "invalid bracketed IPv6 address")
            host, port = match.groups()
            version = 6
        elif value.count(":") == 1:
            host, port = value.split(":")
            version = 4
        else:
            host, version = value, 6 if ":" in value else 4
        # Scope names require a host-specific lookup by the runtime. Refuse them
        # rather than claim this offline tool verified their meaning.
        if "%" in host:
            self.fail(original, "scoped IPv6 is outside this offline migration subset")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            self.fail(original, "address requires a literal numeric IPv4 or IPv6 host")
        if ip.version != version:
            self.fail(original, "address family does not match its syntax")
        if port is not None:
            if not re.fullmatch(r"[0-9]+", port) or not 1 <= int(port) <= 65535:
                self.fail(original, "invalid socket port")
        if seen is not None:
            identity = (ip.version, int(ip), 53 if port is None else int(port))
            if identity in seen:
                self.fail(original, "duplicate numeric listener address")
            seen.add(identity)
        return original

    def plugin(self, tag, kind):
        value = self.plugins.get(tag)
        if value is None or value["type"] != kind:
            self.fail(value, f"{tag!r} must identify a {kind} plugin")
        if tag in self.used:
            self.fail(value, f"plugin reused in incompatible roles: {tag}")
        self.used.add(tag)
        return value["args"]

    def rule(self, value, matches=None):
        self.mapping(value, ("matches", "exec"), ("exec",))
        if matches is None:
            if "matches" in value:
                self.fail(value, "expected an unconditional site-only action")
        elif value.get("matches") != [matches]:
            self.fail(value, f"expected the sole matcher {matches!r}")
        return re.split(r" +", self.string(value["exec"]))

    def reference(self, tokens, value):
        if len(tokens) != 1 or not tokens[0].startswith("$") or len(tokens[0]) == 1:
            self.fail(value, "expected one unqualified $plugin action")
        return tokens[0][1:]

    def goto(self, tokens, value):
        if len(tokens) != 2 or tokens[0] != "goto":
            self.fail(value, "expected an exact goto action")
        return tokens[1]

    def forward(self, tag, prefix):
        args = self.mapping(self.plugin(tag, "forward"),
                            ("upstreams", "concurrent", "so_mark", "bind_to_device"), ("upstreams",))
        for item in self.sequence(args["upstreams"]):
            self.mapping(item, ("addr",), ("addr",))
            self.emit(prefix + "_upstream", self.address(item["addr"], upstream=True))
        self.emit(prefix + "_mark", self.integer(args.get("so_mark", "0"), 0, UINT32_MAX))
        if "bind_to_device" in args:
            device = self.string(args["bind_to_device"])
            if len(device) > 63 or "/" in device or "\\" in device or any(not 33 <= ord(c) <= 126 for c in device):
                self.fail(device, "interface must be 1..63 printable ASCII bytes without spaces or slashes")
            self.emit(prefix + "_interface", device)
        self.emit(prefix + "_concurrent", self.integer(args.get("concurrent", "1"), 1, 3))

    def nft(self, tokens, value):
        if not 2 <= len(tokens) <= 3 or tokens[0] != "nftset":
            self.fail(value, "finalization must contain nftset with one or two explicit set specifications")
        seen = set()
        for spec in tokens[1:]:
            parts = spec.split(",")
            if len(parts) != 5:
                self.fail(value, "nftset requires family,table,set,address_type,mask")
            family, table, name, address_type, mask = parts
            if family not in ("inet", "ip", "ip6") or not NAME.fullmatch(table) or not NAME.fullmatch(name):
                self.fail(value, "invalid nft family/table/set")
            if address_type not in ("ipv4_addr", "ipv6_addr") or address_type in seen:
                self.fail(value, "nft address types must be valid and unique")
            if family not in ("inet", "ip" if address_type == "ipv4_addr" else "ip6"):
                self.fail(value, "nft family does not match its address type")
            seen.add(address_type)
            maximum = 32 if address_type == "ipv4_addr" else 128
            if not re.fullmatch(r"[0-9]+", mask):
                self.fail(value, f"nft mask must be explicit and in 1..{maximum}")
            marked_mask = MarkedString(mask)
            marked_mask.line = getattr(value, "line", 1)
            number = self.integer(marked_mask, 1, maximum)
            key = "nftset_ipv4" if address_type == "ipv4_addr" else "nftset_ipv6"
            # Keep semantic value while preventing legacy leading zeroes from
            # exceeding the runtime nft parser's 512-byte buffer.
            self.emit(key, ",".join(parts[:4] + [str(number)]))

    def convert(self, text):
        root = self.mapping(self.read(text), ("log", "plugins"), ("plugins",))
        if "log" in root:
            log = self.mapping(root["log"], ("level",))
            if log.get("level", "info") != "info":
                self.fail(log, "only the default info logging configuration is migratable")
        listeners = []
        for plugin in self.sequence(root["plugins"], maximum=7 + MAX_ITEMS):
            self.mapping(plugin, ("tag", "type", "args"), ("type", "args"))
            kind = self.string(plugin["type"])
            if kind not in ("domain_set", "cache", "forward", "sequence", "udp_server", "tcp_server"):
                self.fail(plugin, f"unsupported plugin type: {kind}")
            tag = plugin.get("tag")
            if tag is not None:
                tag = self.string(tag)
                if not TAG.fullmatch(tag) or tag in self.plugins:
                    self.fail(plugin, "invalid or duplicate plugin tag")
                self.plugins[tag] = plugin
            if kind in ("udp_server", "tcp_server"):
                listeners.append(plugin)
            elif tag is None:
                self.fail(plugin, "all non-listener plugins require unique tags")
        self.sequence(listeners, maximum=MAX_ITEMS)
        entry = None
        tcp_idle = None
        seen_listeners = {"udp_server": set(), "tcp_server": set()}
        for listener in listeners:
            kind = listener["type"]
            args = self.mapping(listener["args"],
                                ("listen", "entry", "idle_timeout") if kind == "tcp_server" else ("listen", "entry"),
                                ("listen", "entry"))
            candidate = self.string(args["entry"])
            if entry is not None and entry != candidate:
                self.fail(args, "all listeners must use the same entry sequence")
            entry = candidate
            if kind == "tcp_server":
                idle = self.integer(args.get("idle_timeout", "10"), 1, 86400)
                if tcp_idle is not None and tcp_idle != idle:
                    self.fail(args, "per-listener TCP idle timeouts cannot be represented")
                tcp_idle = idle
            self.emit("listen_tcp" if kind == "tcp_server" else "listen_udp", self.address(args["listen"], seen=seen_listeners[kind]))
            if listener.get("tag") is not None:
                self.used.add(listener["tag"])
        if tcp_idle is not None:
            self.emit("tcp_idle_timeout", tcp_idle)

        main = self.sequence(self.plugin(entry, "sequence"), 5, 5)
        cache_tag = self.reference(self.rule(main[0]), main[0])
        finalize_tag = self.goto(self.rule(main[1], "has_resp"), main[1])
        match = main[2].get("matches") if isinstance(main[2], dict) else None
        if not isinstance(match, list) or len(match) != 1 or not isinstance(match[0], str):
            self.fail(main[2], "expected one qname $domain_set matcher")
        match_tokens = re.split(r" +", self.string(match[0]))
        if len(match_tokens) != 2 or match_tokens[0] != "qname" or not match_tokens[1].startswith("$"):
            self.fail(main[2], "expected one qname $domain_set matcher")
        domain_tag = match_tokens[1][1:]
        cn_tag = self.goto(self.rule(main[2], match[0]), main[2])
        foreign_tag = self.reference(self.rule(main[3]), main[3])
        if self.goto(self.rule(main[4]), main[4]) != finalize_tag:
            self.fail(main[4], "foreign path must use the same finalization")

        domain = self.mapping(self.plugin(domain_tag, "domain_set"), ("files",), ("files",))
        for path in self.sequence(domain["files"]):
            self.emit("cn_domain_file", self.string(path))
        cache = self.mapping(self.plugin(cache_tag, "cache"), ("size", "lazy_cache_ttl"))
        # Legacy size=0 means 1024, not disabled. Reject rather than reinterpret.
        self.emit("cache_size", self.integer(cache.get("size", "1024"), 1, 10000000))
        self.emit("cache_lazy_ttl", self.integer(cache.get("lazy_cache_ttl", "0"), 0, UINT32_MAX))
        cn = self.sequence(self.plugin(cn_tag, "sequence"), 2, 2)
        direct_tag = self.reference(self.rule(cn[0]), cn[0])
        if self.goto(self.rule(cn[1]), cn[1]) != finalize_tag:
            self.fail(cn[1], "CN path must use the same finalization")
        self.forward(direct_tag, "cn")
        self.forward(foreign_tag, "foreign")
        finalize = self.sequence(self.plugin(finalize_tag, "sequence"), 2, 2)
        self.nft(self.rule(finalize[0], match[0]), finalize[0])
        if self.rule(finalize[1]) != ["accept"]:
            self.fail(finalize[1], "finalization must finish with accept")
        if self.used != set(self.plugins):
            self.fail(root, f"unreachable or extra plugins are unsupported: {', '.join(sorted(set(self.plugins) - self.used))}")
        result = "# Migrated site-only configuration; paths remain relative to the process working directory.\n"
        result += "\n".join(self.lines) + "\n"
        if len(result.encode("utf-8")) > MAX_BYTES:
            self.fail(root, "generated configuration exceeds 1 MiB")
        return result


def migrate(text, source="<input>"):
    return Converter(source).convert(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="historical site-only YAML file")
    parser.add_argument("-o", "--output", type=Path,
                        help="create a new .conf file; never overwrite (default: stdout)")
    args = parser.parse_args(argv)
    try:
        # Read at most the bound plus one byte, before decoding or parsing YAML.
        with args.input.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise MigrationError(f"{args.input}:1: YAML input exceeds 1 MiB")
        try:
            decoded = data.decode("utf-8")
        except UnicodeError as error:
            raise MigrationError(f"{args.input}:1: input must be valid UTF-8") from error
        result = migrate(decoded, str(args.input))
        if args.output is None:
            sys.stdout.write(result)
        else:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(result)
    except (MigrationError, OSError, UnicodeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
