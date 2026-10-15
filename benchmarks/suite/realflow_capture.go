//go:build linux

// realflow_capture passively mirrors complete production DNS questions as JSONL.
// Build/test only on GitHub: CGO_ENABLED=0 go build -o realflow-capture realflow_capture.go
// go test realflow_capture.go realflow_capture_test.go
// Example (private output, paired runner reads stdin):
//   realflow-capture -iface lo -dst-port 15363 -seconds 86400 | realflow-runner ...
// It never binds a DNS service socket, sends production replies, or changes nft/routes.
// AF_PACKET requires CAP_NET_RAW/root. Linux loopback supplies a 14-byte Ethernet
// header. The BPF accepts IPv4 TCP/UDP for the selected port, plus fragments so
// unsupported fragmentation is counted. IPv6 and pre-existing TCP connections
// without an observed SYN are NOT covered. TCP timestamps denote the packet which
// completes a DNS frame; kernel SO_TIMESTAMPNS is wall time, receive_mono_ns is
// the local monotonic read time (not a claimed kernel monotonic timestamp).
// Query wire is unchanged (including ID, flags, EDNS and all QTYPEs). stdout is
// sensitive: the caller must create private 0700 directories / 0600 files.
// The bounded output queue never stalls packet reads. Queue losses and AF_PACKET
// kernel drops invalidate complete-flow claims; counters are emitted periodically
// and the final summary is also written to stderr even if stdout is blocked.
package main

import (
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "flag"
    "fmt"
    "net"
    "os"
    "os/signal"
    "regexp"
    "strings"
    "sync/atomic"
    "syscall"
    "time"
    "unsafe"
)

const captureVersion = "diversion-realflow-capture-v1"
const maxDNSWire = 65535

type captureCounters map[string]uint64

type capturedPacket struct {
    srcIP, dstIP string
    srcPort, dstPort int
    transport string
    seq uint32
    flags byte
    payload []byte
    index uint64
    unixNS, monoNS int64
    timestampSource string
}

type queryEvent struct {
    Type string `json:"type"`
    Sequence uint64 `json:"sequence"`
    TSUnixNS int64 `json:"ts_unix_ns"`
    ReceiveMonoNS int64 `json:"receive_mono_ns"`
    TimestampSource string `json:"timestamp_source"`
    Transport string `json:"transport"`
    WireB64 string `json:"wire_b64"`
    SrcIP string `json:"src_ip"`
    SrcPort int `json:"src_port"`
    DstIP string `json:"dst_ip"`
    DstPort int `json:"dst_port"`
    FlowID string `json:"flow_id"`
    PacketIndex uint64 `json:"packet_index"`
    Name string `json:"name,omitempty"`
    QType uint16 `json:"qtype,omitempty"`
}

type tcpSegment struct { seq uint32; data []byte }
type captureFlow struct {
    id string
    initial, next uint32
    lastMono, gapSince int64
    pending []tcpSegment
    pendingBytes int
    buffer []byte
}

type captureDecoder struct {
    port int
    maxFlows, maxFlowBytes, maxPending int
    idleNS, gapNS int64
    flows map[string]*captureFlow
    counters captureCounters
    sequence, flowSequence uint64
    emit func(queryEvent)
}

var healthName = regexp.MustCompile(`^r-[0-9]+-[0-9]+-[0-9]+-(a|aaaa)\.(qq\.com|example\.com)$`)

func newCaptureDecoder(port int, emit func(queryEvent)) *captureDecoder {
    return &captureDecoder{port:port, maxFlows:256, maxFlowBytes:262144, maxPending:128,
        idleNS:int64(60*time.Second), gapNS:int64(5*time.Second), flows:make(map[string]*captureFlow),
        counters:make(captureCounters), emit:emit}
}

func readQuestion(wire []byte) (string, uint16, error) {
    if len(wire)<12 || binary.BigEndian.Uint16(wire[4:6])==0 { return "",0,fmt.Errorf("no question") }
    pos,end,total:=12,-1,0
    labels:=[]string{}
    seen:=make(map[int]bool)
    for steps:=0;steps<256;steps++ {
        if pos>=len(wire)||seen[pos] { return "",0,fmt.Errorf("invalid name") }
        seen[pos]=true
        count:=int(wire[pos]); pos++
        if count&0xc0==0xc0 {
            if pos>=len(wire) { return "",0,fmt.Errorf("short pointer") }
            if end<0 { end=pos+1 }
            pos=((count&63)<<8)|int(wire[pos]); continue
        }
        if count&0xc0!=0 { return "",0,fmt.Errorf("reserved label") }
        if count==0 {
            if end<0 {end=pos}
            if end+4>len(wire) {return "",0,fmt.Errorf("short question")}
            return strings.ToLower(strings.Join(labels,".")),binary.BigEndian.Uint16(wire[end:end+2]),nil
        }
        total+=count+1
        if total>254||pos+count>len(wire) {return "",0,fmt.Errorf("long or short name")}
        labels=append(labels,string(wire[pos:pos+count])); pos+=count
    }
    return "",0,fmt.Errorf("too many name steps")
}

func decodeIPv4Frame(frame []byte, port int) (capturedPacket,string) {
    var p capturedPacket
    if len(frame)<14 {return p,"short_ethernet"}
    if binary.BigEndian.Uint16(frame[12:14])!=0x0800 {return p,"non_ipv4"}
    ip:=frame[14:]
    if len(ip)<20||ip[0]>>4!=4 {return p,"short_or_invalid_ipv4"}
    ihl:=int(ip[0]&15)*4
    total:=int(binary.BigEndian.Uint16(ip[2:4]))
    if ihl<20||ihl>len(ip)||total<ihl||total>len(ip) {return p,"truncated_or_invalid_ipv4"}
    if binary.BigEndian.Uint16(ip[6:8])&0x3fff!=0 {return p,"ipv4_fragment_unsupported"}
    p.srcIP=net.IP(ip[12:16]).String(); p.dstIP=net.IP(ip[16:20]).String()
    data:=ip[ihl:total]
    switch ip[9] {
    case 17:
        if len(data)<8 {return p,"short_udp"}
        length:=int(binary.BigEndian.Uint16(data[4:6]))
        if length<8||length>len(data) {return p,"truncated_or_invalid_udp"}
        p.srcPort=int(binary.BigEndian.Uint16(data[:2]));p.dstPort=int(binary.BigEndian.Uint16(data[2:4]))
        if p.dstPort!=port {return p,"other_port"}
        p.transport="udp";p.payload=data[8:length]
    case 6:
        if len(data)<20 {return p,"short_tcp"}
        h:=int(data[12]>>4)*4
        if h<20||h>len(data) {return p,"truncated_or_invalid_tcp"}
        p.srcPort=int(binary.BigEndian.Uint16(data[:2]));p.dstPort=int(binary.BigEndian.Uint16(data[2:4]))
        if p.dstPort!=port {return p,"other_port"}
        p.transport="tcp";p.seq=binary.BigEndian.Uint32(data[4:8]);p.flags=data[13];p.payload=data[h:]
    default: return p,"other_ip_protocol"
    }
    return p,""
}

func (d *captureDecoder) query(p capturedPacket, wire []byte, flowID string) {
    d.counters["dns_messages_total"]++
    if len(wire)<12 {d.counters["dns_short_unsupported"]++;return}
    if binary.BigEndian.Uint16(wire[2:4])&0x8000!=0 {d.counters["dns_response_excluded"]++;return}
    name,qtype,err:=readQuestion(wire)
    if err!=nil {d.counters["dns_question_parse_failed"]++}
    d.counters["dns_queries_total"]++
    if err==nil && healthName.MatchString(name) {d.counters["health_excluded"]++;return}
    d.sequence++
    d.counters["dns_events_emitted"]++
    if d.emit!=nil {d.emit(queryEvent{Type:"dns_query",Sequence:d.sequence,TSUnixNS:p.unixNS,
        ReceiveMonoNS:p.monoNS,TimestampSource:p.timestampSource,Transport:p.transport,
        WireB64:base64.StdEncoding.EncodeToString(wire),SrcIP:p.srcIP,SrcPort:p.srcPort,
        DstIP:p.dstIP,DstPort:p.dstPort,FlowID:flowID,PacketIndex:p.index,Name:name,QType:qtype})}
}

func packetFlowKey(p capturedPacket) string {return fmt.Sprintf("%s:%d>%s:%d",p.srcIP,p.srcPort,p.dstIP,p.dstPort)}
func (d *captureDecoder) dropFlow(key,reason string) {
    f:=d.flows[key]
    if f==nil {return}
    d.counters[reason]++
    if len(f.buffer)>0||len(f.pending)>0 {d.counters["tcp_incomplete_flows"]++}
    delete(d.flows,key)
}
func (d *captureDecoder) expire(now int64, final bool) {
    for key,f:=range d.flows {
        if final {d.dropFlow(key,"tcp_final_flows")} else if now-f.lastMono>d.idleNS {d.dropFlow(key,"tcp_idle_expired")
        } else if len(f.pending)>0&&now-f.gapSince>d.gapNS {d.dropFlow(key,"tcp_gap_expired")}
    }
}
func (d *captureDecoder) appendTCP(key string,f *captureFlow,p capturedPacket,data []byte) bool {
    if len(f.buffer)+f.pendingBytes+len(data)>d.maxFlowBytes {d.dropFlow(key,"tcp_buffer_limit");return false}
    f.next+=uint32(len(data));f.buffer=append(f.buffer,data...)
    for len(f.buffer)>=2 {
        size:=int(binary.BigEndian.Uint16(f.buffer[:2]))
        if size<12||size>maxDNSWire {d.dropFlow(key,"tcp_invalid_dns_length");return false}
        if len(f.buffer)<2+size {break}
        d.query(p,f.buffer[2:2+size],f.id)
        f.buffer=f.buffer[2+size:]
    }
    // Release retained packet backing storage after consuming a large DNS frame.
    if len(f.buffer)==0 {f.buffer=nil}
    return true
}

func (d *captureDecoder) acceptTCP(p capturedPacket) {
    key:=packetFlowKey(p); f:=d.flows[key]
    if p.flags&2!=0 {
        if f!=nil && f.initial==p.seq {d.counters["tcp_syn_retransmitted"]++
        } else {
            if f!=nil {d.dropFlow(key,"tcp_replaced_flows")}
            if len(d.flows)>=d.maxFlows {
                oldest:="";var oldestAt int64
                for k,v:=range d.flows {if oldest==""||v.lastMono<oldestAt {oldest,oldestAt=k,v.lastMono}}
                d.dropFlow(oldest,"tcp_flow_limit_evicted")
            }
            d.flowSequence++
            f=&captureFlow{id:fmt.Sprintf("%s#%d",key,d.flowSequence),initial:p.seq,next:p.seq+1,lastMono:p.monoNS}
            d.flows[key]=f;d.counters["tcp_syn_flows"]++
        }
        p.seq++ // SYN consumes one sequence number before any SYN payload.
    }
    if f==nil {
        if len(p.payload)>0 {d.counters["tcp_without_syn_payload_packets"]++}
        return
    }
    f.lastMono=p.monoNS
    if p.flags&4!=0 {d.dropFlow(key,"tcp_reset_flows");return}
    data:=p.payload;seq:=p.seq
    if len(data)>0 {
        offset:=int64(int32(seq-f.next))
        if offset<0 {
            trim:=-offset
            if trim>=int64(len(data)) {d.counters["tcp_retransmitted_packets"]++;data=nil
            } else {d.counters["tcp_overlap_trimmed_packets"]++;data=data[trim:];seq=f.next;offset=0}
        }
        if len(data)>0&&offset>0 {
            if offset>int64(d.maxFlowBytes)||len(f.pending)>=d.maxPending||len(f.buffer)+f.pendingBytes+len(data)>d.maxFlowBytes {
                d.dropFlow(key,"tcp_gap_or_pending_limit");return
            }
            // Overlapping pending segments must agree; keep each bounded segment
            // and trim duplicates when contiguous bytes become available.
            for _,s:=range f.pending {
                delta:=int64(int32(seq-s.seq));a,b:=int64(0),delta
                if delta<0 {a=-delta;b=0}
                n:=int64(len(data))-a
                if other:=int64(len(s.data))-b;other<n {n=other}
                if n>0 {
                    if string(data[a:a+n])!=string(s.data[b:b+n]) {d.dropFlow(key,"tcp_conflicting_overlap");return}
                    if seq==s.seq&&len(data)==len(s.data) {d.counters["tcp_retransmitted_packets"]++;return}
                }
            }
            if len(f.pending)==0 {f.gapSince=p.monoNS}
            f.pending=append(f.pending,tcpSegment{seq:seq,data:append([]byte(nil),data...)})
            f.pendingBytes+=len(data);d.counters["tcp_out_of_order_packets"]++
        } else if len(data)>0 {
            if !d.appendTCP(key,f,p,data) {return}
        }
        for len(f.pending)>0 {
            chosen:=-1
            for i,s:=range f.pending {if int32(s.seq-f.next)<=0 {chosen=i;break}}
            if chosen<0 {break}
            s:=f.pending[chosen]
            copy(f.pending[chosen:],f.pending[chosen+1:]);f.pending[len(f.pending)-1]=tcpSegment{};f.pending=f.pending[:len(f.pending)-1];f.pendingBytes-=len(s.data)
            trim:=int64(int32(f.next-s.seq))
            if trim>=int64(len(s.data)) {continue}
            if !d.appendTCP(key,f,p,s.data[trim:]) {return}
        }
    }
    if len(f.pending)==0 {f.gapSince=0}
    if p.flags&1!=0 {
        // An out-of-order FIN cannot establish whether a missing DNS frame was
        // complete; mark that flow incomplete and stop mirroring it explicitly.
        d.dropFlow(key,"tcp_fin_flows")
    }
}

func (d *captureDecoder) frame(frame []byte, index uint64, unixNS,monoNS int64,source string) {
    p,reason:=decodeIPv4Frame(frame,d.port)
    if reason!="" {d.counters[reason]++;return}
    p.index=index;p.unixNS=unixNS;p.monoNS=monoNS;p.timestampSource=source
    d.counters[p.transport+"_packets"]++
    if p.transport=="udp" {d.query(p,p.payload,packetFlowKey(p))} else {d.acceptTCP(p)}
}

func hostToNetwork16(value uint16) uint16 {
    var b [2]byte;binary.BigEndian.PutUint16(b[:],value)
    return *(*uint16)(unsafe.Pointer(&b[0]))
}

func captureFilter(port int) []syscall.SockFilter {
    // Ethernet IPv4; TCP/UDP only; IHL-aware destination port. Fragments are
    // deliberately accepted only to count unsupported IP reassembly.
    return []syscall.SockFilter{
        {Code:0x28,K:12}, {Code:0x15,Jt:0,Jf:10,K:0x0800},
        {Code:0x30,K:23}, {Code:0x15,Jt:1,Jf:0,K:6}, {Code:0x15,Jt:0,Jf:7,K:17},
        {Code:0x28,K:20}, {Code:0x45,Jt:4,Jf:0,K:0x3fff},
        {Code:0xb1,K:14}, {Code:0x48,K:16}, {Code:0x15,Jt:1,Jf:2,K:uint32(port)},
        {Code:0x06,K:0}, {Code:0x06,K:65535+14}, {Code:0x06,K:0},
    }
}

func attachCaptureFilter(fd,port int) error {
    filter:=captureFilter(port)
    prog:=syscall.SockFprog{Len:uint16(len(filter)),Filter:&filter[0]}
    _,_,errno:=syscall.Syscall6(syscall.SYS_SETSOCKOPT,uintptr(fd),syscall.SOL_SOCKET,syscall.SO_ATTACH_FILTER,
        uintptr(unsafe.Pointer(&prog)),unsafe.Sizeof(prog),0)
    if errno!=0 {return errno};return nil
}

func captureMonotonicNS() int64 {
    var ts syscall.Timespec
    _,_,errno:=syscall.Syscall(syscall.SYS_CLOCK_GETTIME,1,uintptr(unsafe.Pointer(&ts)),0)
    if errno!=0 {return 0}
    return int64(ts.Sec)*1e9+int64(ts.Nsec)
}

func kernelCaptureTimestamp(control []byte,fallback int64) (int64,string) {
    messages,err:=syscall.ParseSocketControlMessage(control)
    if err!=nil {return fallback,"receive_wall_fallback"}
    for _,m:=range messages {
        if m.Header.Level==syscall.SOL_SOCKET && m.Header.Type==syscall.SO_TIMESTAMPNS && len(m.Data)>=int(unsafe.Sizeof(syscall.Timespec{})) {
            ts:=*(*syscall.Timespec)(unsafe.Pointer(&m.Data[0]))
            if ts.Nsec>=0&&ts.Nsec<1e9 {return int64(ts.Sec)*1e9+int64(ts.Nsec),"kernel_so_timestampns"}
        }
    }
    return fallback,"receive_wall_fallback"
}

func readPacketStatistics(fd int) (uint32,uint32,error) {
    var stats [2]uint32
    length:=uint32(unsafe.Sizeof(stats))
    _,_,errno:=syscall.Syscall6(syscall.SYS_GETSOCKOPT,uintptr(fd),263,6,
        uintptr(unsafe.Pointer(&stats[0])),uintptr(unsafe.Pointer(&length)),0)
    if errno!=0 {return 0,0,errno}
    if length<8 {return 0,0,fmt.Errorf("short PACKET_STATISTICS")}
    return stats[0],stats[1],nil
}

func captureMain() int {
    ifaceFlag:=flag.String("iface","lo","AF_PACKET interface (lo required for this deployment)")
    port:=flag.Int("dst-port",15363,"production destination port to passively mirror")
    seconds:=flag.Int("seconds",86400,"hard capture lease in seconds (1..172800)")
    statsSeconds:=flag.Int("stats-seconds",30,"counter output interval (1..900)")
    queueSize:=flag.Int("output-queue",256,"bounded JSONL output queue (1..4096)")
    flag.Parse()
    if *port<1||*port>65535||*seconds<1||*seconds>172800||*statsSeconds<1||*statsSeconds>900||*queueSize<1||*queueSize>4096 {fmt.Fprintln(os.Stderr,"invalid capture bounds");return 2}
    iface,err:=net.InterfaceByName(*ifaceFlag)
    if err!=nil {fmt.Fprintln(os.Stderr,err);return 2}
    fd,err:=syscall.Socket(syscall.AF_PACKET,syscall.SOCK_RAW|syscall.SOCK_CLOEXEC,int(hostToNetwork16(0x0800)))
    if err!=nil {fmt.Fprintln(os.Stderr,err);return 2}
    defer syscall.Close(fd)
    if err=syscall.Bind(fd,&syscall.SockaddrLinklayer{Protocol:hostToNetwork16(0x0800),Ifindex:iface.Index});err!=nil {fmt.Fprintln(os.Stderr,err);return 2}
    if err=attachCaptureFilter(fd,*port);err!=nil {fmt.Fprintln(os.Stderr,"BPF:",err);return 2}
    if err=syscall.SetsockoptInt(fd,syscall.SOL_SOCKET,syscall.SO_RCVBUF,4*1024*1024);err!=nil {fmt.Fprintln(os.Stderr,"receive buffer:",err);return 2}
    if err=syscall.SetsockoptInt(fd,syscall.SOL_SOCKET,syscall.SO_TIMESTAMPNS,1);err!=nil {fmt.Fprintln(os.Stderr,"timestamp:",err);return 2}
    if err=syscall.SetsockoptTimeval(fd,syscall.SOL_SOCKET,syscall.SO_RCVTIMEO,&syscall.Timeval{Sec:1});err!=nil {fmt.Fprintln(os.Stderr,"receive timeout:",err);return 2}
    output:=make(chan []byte,*queueSize);writerDone:=make(chan struct{});var writeFailed atomic.Bool
    go func(){defer close(writerDone);for line:=range output {if _,e:=os.Stdout.Write(append(line,'\n'));e!=nil {writeFailed.Store(true);fmt.Fprintln(os.Stderr,"capture stdout:",e);return}}}()
    decoder:=newCaptureDecoder(*port,nil)
    enqueue:=func(value any,kind string) {
        line,e:=json.Marshal(value)
        if e!=nil {decoder.counters["json_encode_failed"]++;return}
        select {case output<-line:decoder.counters[kind+"_queued"]++
        default:decoder.counters[kind+"_queue_full"]++}
    }
    decoder.emit=func(q queryEvent){enqueue(q,"events")}
    signals:=make(chan os.Signal,2);signal.Notify(signals,syscall.SIGINT,syscall.SIGTERM);defer signal.Stop(signals)
    start:=time.Now();deadline:=start.Add(time.Duration(*seconds)*time.Second);nextStats:=start
    bootBytes,_:=os.ReadFile("/proc/sys/kernel/random/boot_id");bootID:=strings.TrimSpace(string(bootBytes))
    enqueue(map[string]any{"type":"capture_start","schema":captureVersion,"ts_unix_ns":start.UnixNano(),"receive_mono_ns":captureMonotonicNS(),"pid":os.Getpid(),"boot_id":bootID,"iface":*ifaceFlag,"dst_port":*port,"lease_seconds":*seconds,"output_queue_capacity":*queueSize},"metadata")
    var kernelPackets,kernelDrops uint64
    stats:=func(final bool) map[string]any {
        packets,drops,e:=readPacketStatistics(fd)
        if e!=nil {decoder.counters["packet_statistics_failed"]++} else {kernelPackets+=uint64(packets);kernelDrops+=uint64(drops)}
        counters:=make(captureCounters,len(decoder.counters));for k,v:=range decoder.counters {counters[k]=v}
        return map[string]any{"type":"capture_stats","schema":captureVersion,"ts_unix_ns":time.Now().UnixNano(),
            "receive_mono_ns":captureMonotonicNS(),"pid":os.Getpid(),"boot_id":bootID,"iface":*ifaceFlag,"dst_port":*port,"final":final,
            "elapsed_seconds":time.Since(start).Seconds(),"kernel_packets":kernelPackets,"kernel_drops":kernelDrops,
            "active_tcp_flows":len(decoder.flows),"output_queue_depth":len(output),"counters":counters,
            "limitations":[]string{"IPv4 only","TCP requires captured SYN","IP fragments unsupported","receive_mono_ns is read time; ts_unix_ns is kernel wall time","kernel packet count includes discarded outgoing loopback copies"}}
    }
    buffer:=make([]byte,65535+14);control:=make([]byte,256);var packetIndex uint64;exitCode:=0
captureLoop:
    for time.Now().Before(deadline) {
        select {case <-signals:break captureLoop;default:}
        if writeFailed.Load(){exitCode=1;break}
        now:=time.Now()
        if !now.Before(nextStats) {decoder.expire(captureMonotonicNS(),false);enqueue(stats(false),"stats");nextStats=now.Add(time.Duration(*statsSeconds)*time.Second)}
        n,oobn,flags,from,e:=syscall.Recvmsg(fd,buffer,control,0)
        if e==syscall.EAGAIN||e==syscall.EWOULDBLOCK||e==syscall.EINTR {continue}
        if e!=nil {decoder.counters["recv_failed"]++;fmt.Fprintln(os.Stderr,"capture receive:",e);exitCode=1;break}
        packetIndex++;decoder.counters["socket_packets"]++
        if link,ok:=from.(*syscall.SockaddrLinklayer);ok&&link.Pkttype==4 {decoder.counters["outgoing_duplicates_excluded"]++;continue}
        if flags&syscall.MSG_TRUNC!=0 {decoder.counters["socket_truncated"]++;continue}
        if flags&syscall.MSG_CTRUNC!=0 {decoder.counters["timestamp_control_truncated"]++}
        wall:=time.Now().UnixNano();mono:=captureMonotonicNS();ts,source:=kernelCaptureTimestamp(control[:oobn],wall)
        if source!="kernel_so_timestampns" {decoder.counters["timestamp_fallback"]++}
        decoder.frame(buffer[:n],packetIndex,ts,mono,source)
    }
    decoder.expire(captureMonotonicNS(),true)
    final:=stats(true);line,_:=json.Marshal(final)
    select {case output<-line:case <-time.After(2*time.Second):decoder.counters["final_stats_queue_failed"]++;exitCode=1}
    close(output)
    select {case <-writerDone:case <-time.After(3*time.Second):decoder.counters["stdout_drain_timeout"]++;exitCode=1}
    if writeFailed.Load(){exitCode=1}
    // Refresh counters after drain/final-enqueue failures for the independent stderr receipt.
    final["counters"]=decoder.counters;line,_=json.Marshal(final);fmt.Fprintln(os.Stderr,"capture_final",string(line))
    return exitCode
}
func main(){os.Exit(captureMain())}
