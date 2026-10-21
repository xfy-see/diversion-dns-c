#!/usr/bin/env python3
"""Read-only DNS topology fixtures; no network access or router mutation."""
import pathlib
import unittest

from lupa.lua51 import LuaRuntime

ROOT = pathlib.Path(__file__).parents[1]


class DNSStatusTests(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.lua.execute("package.preload['luci.jsonc']=function() return {parse=function() return nil end} end")
        self.lua.globals().D = self.lua.execute((ROOT / "dns-status.lua").read_text())
        self.lua.execute(r"""
          config='listen_udp=127.0.0.1:15363\nlisten_tcp=127.0.0.1:15363\n'..
            'cn_upstream=192.0.2.53:53\ncn_upstream=192.0.2.54:53\ncn_interface=pppoe-wan\ncn_mark=0\n'..
            'foreign_upstream=1.1.1.1:53\nforeign_upstream=8.8.8.8:53\nforeign_interface=wg_vpn\nforeign_mark=1\n'
          files={['/etc/diversion-dns-c/config.conf']=config}
          server='127.0.0.1#15363';noresolv='1';resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'
          commands={};reads={};route_failure=false;route_wrong=false;service_running=true;service_wrong_config=false
          function parse(raw)
            if raw=='main-service' then return {['diversion-dns-c']={instances={resolver={running=service_running,
              command={'/usr/sbin/diversion-dns-c','start','-c',service_wrong_config and '/other.conf' or '/etc/diversion-dns-c/config.conf','--cpu','2'}}}}} end
            if raw=='filter-service' then return {['pnw-foreign-v4-dns']={instances={filter={running=filter_running,
              command={'/usr/sbin/dnsmasq','--keep-in-foreground','--conf-file=/etc/pnw-control/foreign-v4-dns.conf'}}}}} end
            return nil
          end
          function read(path,limit) reads[#reads+1]=path;return files[path] end
          function run(command)
            commands[#commands+1]=command
            if command=="uci -q get 'dhcp.@dnsmasq[0].server'" then return server,server=='' and 1 or 0 end
            if command=="uci -q get 'dhcp.@dnsmasq[0].noresolv'" then return noresolv,noresolv=='' and 1 or 0 end
            if command=="uci -q get 'dhcp.@dnsmasq[0].resolvfile'" then return resolvfile,resolvfile=='' and 1 or 0 end
            if command==[[ubus call service list '{"name":"diversion-dns-c"}']] then return 'main-service',0 end
            if command==[[ubus call service list '{"name":"pnw-foreign-v4-dns"}']] then return 'filter-service',0 end
            if command:match('^ip %-') then
              if route_failure and command:find('8.8.8.8',1,true) then return 'RTNETLINK answers: Network unreachable',2 end
              if route_wrong and command:find('1.1.1.1',1,true) then return '1.1.1.1 dev pppoe-wan',0 end
              return 'unicast dev '..(command:match("oif '([^']+)'$") or 'pppoe-wan'),0
            end
            error('unexpected command '..command)
          end
          function get() return D.get({read=read,run=run,parse=parse,now=function() return 1792320000 end}) end
        """)

    def test_live_topology_whitelisted_addresses(self):
        self.lua.execute(r"""
          local r=get();assert(r.cn.available and r.foreign.available)
          assert(#r.cn.upstreams==2 and r.cn.upstreams[1]=='192.0.2.53:53')
          assert(r.foreign.upstreams[2]=='8.8.8.8:53' and r.foreign.interface=='wg_vpn' and r.foreign.mark==1)
          assert(r.cn.interface=='pppoe-wan' and r.cn.mark==0 and r.cn.mode=='diversion')
          assert(r.observed_at==1792320000 and r.source=='/etc/diversion-dns-c/config.conf')
          assert(r.listeners==nil and r.command==nil and r.env==nil)
        """)

    def test_stopped_and_wrong_service_not_active(self):
        self.lua.execute(r"""
          service_running=false;local r=get();assert(not r.cn.available and not r.foreign.available)
          assert(#r.cn.upstreams==2 and r.cn.reason:find('not running',1,true))
          service_running=true;service_wrong_config=true;assert(not get().cn.available)
        """)

    def test_dnsmasq_bypass_and_conditional_forwarders_are_unknown(self):
        self.lua.execute(r"""
          server='1.1.1.1';local r=get();assert(not r.cn.available and r.cn.reason:find('does not match',1,true))
          server='127.0.0.1#15363 1.1.1.1';assert(not get().foreign.available)
          server='/example.com/127.0.0.1#15363';assert(not get().foreign.available)
        """)

    def test_missing_route_is_not_an_active_foreign_upstream(self):
        self.lua.execute(r"""
          route_failure=true;local r=get();assert(r.cn.available and not r.foreign.available)
          assert(r.foreign.reason:find('route',1,true))
          route_failure=false;route_wrong=true;r=get();assert(r.cn.available and not r.foreign.available)
        """)

    def test_degraded_mode_uses_actual_common_servers(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/degraded']='';server='192.0.2.53 192.0.2.54'
          local r=get();assert(not r.cn.available and not r.foreign.available)
          assert(r.cn.mode=='degraded-dnsmasq' and r.foreign.upstreams[1]=='192.0.2.53:53')
          assert(r.foreign.reason:find('split is inactive',1,true))
          for _,command in ipairs(commands) do assert(not command:find('route get',1,true)) end
        """)

    def test_resolv_fallback_and_noresolv_source_selection(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/degraded']='';server='';noresolv='0'
          files[resolvfile]='# nameserver 9.9.9.9\nnameserver 192.0.2.53\nnameserver 2001:db8:1::1\n'
          local r=get();assert(#r.cn.upstreams==2 and r.cn.upstreams[2]=='[2001:db8:1::1]:53')
          assert(r.source:find(resolvfile,1,true))
          noresolv='1';reads={};r=get();assert(#r.cn.upstreams==0)
          for _,path in ipairs(reads) do assert(path~=resolvfile) end
        """)

    def test_ipv6_dnsmasq_server_port_is_preserved(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/degraded']='';server='2001:db8:1::1#5353 [2001:db8:1::2]#5354'
          local r=get();assert(#r.cn.upstreams==2)
          assert(r.cn.upstreams[1]=='[2001:db8:1::1]:5353' and r.cn.upstreams[2]=='[2001:db8:1::2]:5354')
        """)

    def test_unknown_resolv_file_cannot_read_secrets(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/degraded']='';server='';noresolv='0'
          for _,path in ipairs({'/etc/shadow','/tmp/resolv/../../etc/shadow','/tmp/resolv$(id)'}) do
            resolvfile=path;reads={};local r=get();assert(#r.cn.upstreams==0)
            assert(r.cn.reason:find('unavailable',1,true))
            for _,readpath in ipairs(reads) do assert(readpath~=path) end
          end
        """)

    def test_unrecognized_values_and_secrets_are_never_emitted(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/config.conf']=config..'private_key=secret\napi_secret=secret\n'
          local r=get();assert(r.cn.available and r.private_key==nil and r.cn.api_secret==nil)
          for _,extra in ipairs({'cn_upstream=tcp://user:secret@1.1.1.1:53\n','cn_interface=$(id)\n','foreign_mark=4294967296\n'}) do
            files['/etc/diversion-dns-c/config.conf']=config..extra;commands={};r=get()
            assert(not r.cn.available and not r.foreign.available)
            for _,cmd in ipairs(commands) do assert(not cmd:find('secret',1,true) and not cmd:find('$(id)',1,true)) end
            for _,address in ipairs(r.cn.upstreams) do assert(not address:find('secret',1,true)) end
          end
        """)

    def test_ipv6_tcp_mark_and_implicit_mark_defaults(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/config.conf']=config:gsub('1.1.1.1:53','tcp://[2606:4700:4700::1111]:853'):
            gsub('foreign_mark=1','foreign_mark=0x1'):gsub('cn_mark=0\n','')
          local r=get();assert(r.foreign.available and r.cn.mark==0)
          assert(r.foreign.upstreams[1]=='tcp://[2606:4700:4700::1111]:853')
          local saw=false;for _,cmd in ipairs(commands) do if cmd:find("ip -6 route get '2606:4700:4700::1111' mark 1",1,true) then saw=true end end;assert(saw)
        """)

    def test_foreign_ipv4_filter_displays_both_hops(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/config.conf']=config:gsub('foreign_upstream=1.1.1.1:53\nforeign_upstream=8.8.8.8:53','foreign_upstream=127.0.0.1:15364'):
            gsub('foreign_interface=wg_vpn','foreign_interface=lo')
          files['/etc/pnw-control/foreign-v4-dns.conf']='port=15364\nlisten-address=127.0.0.1\nno-resolv\nserver=1.1.1.1\nserver=8.8.8.8\nfilter-AAAA\n'
          filter_running=true;local r=get();assert(r.cn.available and r.foreign.available)
          assert(r.foreign.mode=='foreign-v4-filter' and r.foreign.upstreams[1]=='127.0.0.1:15364')
          assert(#r.foreign.downstream==2 and r.foreign.downstream[1]=='1.1.1.1:53')
          filter_running=false;r=get();assert(not r.foreign.available and r.foreign.reason:find('not running',1,true))
        """)

    def test_missing_filter_or_mismatched_filter_is_unavailable(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/config.conf']=config:gsub('foreign_upstream=1.1.1.1:53\nforeign_upstream=8.8.8.8:53','foreign_upstream=127.0.0.1:15364')
          local r=get();assert(not r.foreign.available and r.foreign.reason:find('configuration',1,true))
          files['/etc/pnw-control/foreign-v4-dns.conf']='port=15364\nlisten-address=127.0.0.1\nserver=1.1.1.1\nfilter-AAAA\n'
          r=get();assert(not r.foreign.available and r.foreign.reason:find('not recognized',1,true))
        """)

    def test_missing_config_does_not_throw(self):
        self.lua.execute(r"""
          files['/etc/diversion-dns-c/config.conf']=nil
          local r=get();assert(not r.cn.available and not r.foreign.available and r.cn.reason:find('unavailable',1,true))
        """)


if __name__ == "__main__":
    unittest.main(verbosity=2)
