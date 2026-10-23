//go:build linux

package main

import (
    "bytes"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "strings"
    "syscall"
    "testing"
    "unsafe"
)

func captureTestQuery(name string,typ uint16) []byte {
    q:=make([]byte,12);binary.BigEndian.PutUint16(q[:2],0x1234);binary.BigEndian.PutUint16(q[2:4],0x0130)
    binary.BigEndian.PutUint16(q[4:6],1)
    for _,label:=range strings.Split(name,".") {q=append(q,byte(len(label)));q=append(q,label...)}
    q=append(q,0,byte(typ>>8),byte(typ),0,1)
    return q
}
func captureTestFrame(protocol byte,port int,payload []byte,seq uint32,flags byte) []byte {
    transport:=make([]byte,8)
    if protocol==6 {transport=make([]byte,20);binary.BigEndian.PutUint32(transport[4:8],seq);transport[12]=0x50;transport[13]=flags}
    binary.BigEndian.PutUint16(transport[:2],45000);binary.BigEndian.PutUint16(transport[2:4],uint16(port))
    if protocol==17 {binary.BigEndian.PutUint16(transport[4:6],uint16(8+len(payload)))}
    ip:=make([]byte,20);ip[0]=0x45;ip[8]=64;ip[9]=protocol
    binary.BigEndian.PutUint16(ip[2:4],uint16(20+len(transport)+len(payload)))
    copy(ip[12:16],[]byte{127,0,0,1});copy(ip[16:20],[]byte{127,0,0,1})
    frame:=make([]byte,14);binary.BigEndian.PutUint16(frame[12:14],0x0800)
    return append(append(append(frame,ip...),transport...),payload...)
}
func captureTestDecoder() (*captureDecoder,*[]queryEvent) {
    events:=[]queryEvent{}
    d:=newCaptureDecoder(15363,func(e queryEvent){events=append(events,e)})
    return d,&events
}
func captureTestFeed(d *captureDecoder,frame []byte,index uint64) {d.frame(frame,index,int64(index)*1000,int64(index)*100,"kernel_so_timestampns")}
func captureTestTCP(d *captureDecoder,seq uint32,flags byte,payload []byte,index uint64) {
    captureTestFeed(d,captureTestFrame(6,15363,payload,seq,flags),index)
}
func captureTestFramed(q []byte) []byte {return append([]byte{byte(len(q)>>8),byte(len(q))},q...)}

func TestCaptureUDPWireUnchangedAllTypes(t *testing.T) {
    for _,typ:=range []uint16{1,28,16,65,255} {
        t.Run(fmt.Sprint(typ),func(t *testing.T){
            d,events:=captureTestDecoder();q:=captureTestQuery("MiXeD.Example",typ)
            // Preserve EDNS, DO and a DNS cookie rather than synthesizing a question.
            binary.BigEndian.PutUint16(q[10:12],1)
            q=append(q,0,0,41,4,208,0,0,128,0,0,12,0,10,0,8,1,2,3,4,5,6,7,8)
            captureTestFeed(d,captureTestFrame(17,15363,q,0,0),1)
            if len(*events)!=1 {t.Fatalf("events=%d counters=%v",len(*events),d.counters)}
            e:=(*events)[0];wire,err:=base64.StdEncoding.DecodeString(e.WireB64)
            if err!=nil||!bytes.Equal(wire,q)||e.QType!=typ||e.Name!="mixed.example"||e.TSUnixNS!=1000||e.ReceiveMonoNS!=100||e.Transport!="udp" {t.Fatalf("event=%+v wire=%x",e,wire)}
        })
    }
}
func TestCaptureHealthExclusionExact(t *testing.T) {
    d,events:=captureTestDecoder()
    names:=[]string{"r-12-34-56-a.qq.com","R-1-2-3-AAAA.EXAMPLE.COM","r-1-2-3-a.qq.com.attacker","r-1-2-a.qq.com","www.qq.com"}
    for i,n:=range names {captureTestFeed(d,captureTestFrame(17,15363,captureTestQuery(n,1),0,0),uint64(i+1))}
    if len(*events)!=3||d.counters["health_excluded"]!=2||d.counters["dns_queries_total"]!=5 {t.Fatalf("events=%v counters=%v",*events,d.counters)}
}
func TestCaptureMalformedQuestionStillMirrored(t *testing.T) {
    d,events:=captureTestDecoder();q:=captureTestQuery("bad.example",1);q[12]=0xc0;q[13]=12
    captureTestFeed(d,captureTestFrame(17,15363,q,0,0),1)
    if len(*events)!=1||d.counters["dns_question_parse_failed"]!=1 {t.Fatalf("events=%v counters=%v",*events,d.counters)}
}
func TestCaptureShortAndResponseAccounting(t *testing.T) {
    d,events:=captureTestDecoder();q:=captureTestQuery("answer.example",1);q[2]|=0x80
    captureTestFeed(d,captureTestFrame(17,15363,q,0,0),1)
    captureTestFeed(d,captureTestFrame(17,15363,[]byte{1},0,0),2)
    if len(*events)!=0||d.counters["dns_response_excluded"]!=1||d.counters["dns_short_unsupported"]!=1||d.counters["dns_messages_total"]!=2 {t.Fatal(d.counters)}
}
func TestCaptureReadQuestionCompressionAndBounds(t *testing.T) {
    q:=captureTestQuery("a.example",65)
    name,typ,err:=readQuestion(q)
    if err!=nil||name!="a.example"||typ!=65 {t.Fatalf("%s %d %v",name,typ,err)}
    cases:=[][]byte{nil,q[:14],append(append([]byte(nil),q[:12]...),0xc0,12),append(append([]byte(nil),q[:12]...),0x40)}
    for i,c:=range cases {if _,_,err:=readQuestion(c);err==nil {t.Fatalf("bad case %d accepted",i)}}
}
func TestCaptureFrameRejects(t *testing.T) {
    good:=captureTestFrame(17,15363,captureTestQuery("test.example",1),0,0)
    cases:=map[string][]byte{}
    cases["short_ethernet"]=good[:4]
    f:=append([]byte(nil),good...);f[12]=0x86;f[13]=0xdd;cases["non_ipv4"]=f
    f=append([]byte(nil),good...);f[14]=0x44;cases["truncated_or_invalid_ipv4"]=f
    cases["truncated_or_invalid_ipv4"]=good[:len(good)-1]
    f=append([]byte(nil),good...);f[20]=0x20;cases["ipv4_fragment_unsupported"]=f
    f=append([]byte(nil),good...);binary.BigEndian.PutUint16(f[36:38],53);cases["other_port"]=f
    f=append([]byte(nil),good...);binary.BigEndian.PutUint16(f[38:40],65535);cases["truncated_or_invalid_udp"]=f
    for reason,f:=range cases {_,got:=decodeIPv4Frame(f,15363);if got!=reason {t.Fatalf("want %s got %s",reason,got)}}
}
func TestCaptureTCPPrefixSplitAndCoalescing(t *testing.T) {
    d,events:=captureTestDecoder();a:=captureTestFramed(captureTestQuery("a.example",1));b:=captureTestFramed(captureTestQuery("b.example",28))
    captureTestTCP(d,100,2,nil,1)
    captureTestTCP(d,101,0x18,a[:1],2)
    captureTestTCP(d,102,0x18,append(a[1:],b...),3)
    if len(*events)!=2||(*events)[0].Name!="a.example"||(*events)[1].QType!=28||(*events)[1].Sequence!=2 {t.Fatalf("events=%v counters=%v",*events,d.counters)}
}
func TestCaptureTCPOutOfOrderAndRetransmission(t *testing.T) {
    d,events:=captureTestDecoder();q:=captureTestFramed(captureTestQuery("order.example",1))
    captureTestTCP(d,100,2,nil,1)
    captureTestTCP(d,111,0x18,q[10:],2)
    captureTestTCP(d,111,0x18,q[10:],3)
    captureTestTCP(d,101,0x18,q[:10],4)
    captureTestTCP(d,101,0x18,q,5)
    if len(*events)!=1||d.counters["tcp_retransmitted_packets"]!=2||d.counters["tcp_out_of_order_packets"]!=1 {t.Fatalf("events=%v counters=%v",*events,d.counters)}
}
func TestCaptureTCPPartialOverlapTrim(t *testing.T) {
    d,events:=captureTestDecoder();q:=captureTestFramed(captureTestQuery("overlap.example",1))
    captureTestTCP(d,100,2,nil,1)
    captureTestTCP(d,101,0x18,q[:10],2)
    captureTestTCP(d,106,0x18,q[5:],3)
    if len(*events)!=1||d.counters["tcp_overlap_trimmed_packets"]!=1 {t.Fatalf("events=%v counters=%v",*events,d.counters)}
}
func TestCaptureTCPSequenceWrap(t *testing.T) {
    d,events:=captureTestDecoder();q:=captureTestFramed(captureTestQuery("wrap.example",1));initial:=uint32(0xfffffffc)
    captureTestTCP(d,initial,2,nil,1)
    captureTestTCP(d,initial+1,0x18,q[:10],2)
    next:=initial+uint32(11);captureTestTCP(d,next,0x18,q[10:],3)
    if len(*events)!=1 {t.Fatalf("events=%v counters=%v",*events,d.counters)}
}
func TestCaptureTCPSynPayloadAndRetransmittedSyn(t *testing.T) {
    d,events:=captureTestDecoder();q:=captureTestFramed(captureTestQuery("syn.example",1))
    captureTestTCP(d,100,2,q,1);captureTestTCP(d,100,2,q,2)
    if len(*events)!=1||d.counters["tcp_syn_retransmitted"]!=1 {t.Fatalf("events=%v counters=%v",*events,d.counters)}
}
func TestCaptureTCPWithoutSynAndInvalidLength(t *testing.T) {
    d,events:=captureTestDecoder();captureTestTCP(d,100,0x18,[]byte{0,12},1)
    captureTestTCP(d,100,2,nil,2);captureTestTCP(d,101,0x18,[]byte{0,1,0},3)
    if len(*events)!=0||d.counters["tcp_without_syn_payload_packets"]!=1||d.counters["tcp_invalid_dns_length"]!=1||len(d.flows)!=0 {t.Fatal(d.counters)}
}
func TestCaptureTCPConflictingPendingOverlap(t *testing.T) {
    d,events:=captureTestDecoder();captureTestTCP(d,100,2,nil,1)
    captureTestTCP(d,110,0x18,[]byte("ABCD"),2);captureTestTCP(d,111,0x18,[]byte("xyz"),3)
    if len(*events)!=0||d.counters["tcp_conflicting_overlap"]!=1||d.counters["tcp_incomplete_flows"]!=1 {t.Fatal(d.counters)}
}
func TestCaptureTCPLimits(t *testing.T) {
    t.Run("buffer",func(t *testing.T){d,_:=captureTestDecoder();d.maxFlowBytes=16;captureTestTCP(d,100,2,nil,1);captureTestTCP(d,101,0x18,make([]byte,17),2);if d.counters["tcp_buffer_limit"]!=1 {t.Fatal(d.counters)}})
    t.Run("pending",func(t *testing.T){d,_:=captureTestDecoder();d.maxPending=1;captureTestTCP(d,100,2,nil,1);captureTestTCP(d,111,0x18,[]byte{1},2);captureTestTCP(d,121,0x18,[]byte{2},3);if d.counters["tcp_gap_or_pending_limit"]!=1 {t.Fatal(d.counters)}})
    t.Run("flows",func(t *testing.T){d,_:=captureTestDecoder();d.maxFlows=1;captureTestTCP(d,100,2,nil,1);f:=captureTestFrame(6,15363,nil,200,2);binary.BigEndian.PutUint16(f[34:36],45001);captureTestFeed(d,f,2);if d.counters["tcp_flow_limit_evicted"]!=1||len(d.flows)!=1 {t.Fatal(d.counters)}})
}
func TestCaptureTCPExpiryAndFIN(t *testing.T) {
    t.Run("gap",func(t *testing.T){d,_:=captureTestDecoder();captureTestTCP(d,100,2,nil,1);captureTestTCP(d,110,0x18,[]byte{1},2);captureTestTCP(d,101,0x10,nil,3);d.expire(201+d.gapNS,false);if d.counters["tcp_gap_expired"]!=1||d.counters["tcp_incomplete_flows"]!=1 {t.Fatal(d.counters)}})
    t.Run("idle",func(t *testing.T){d,_:=captureTestDecoder();captureTestTCP(d,100,2,nil,1);d.expire(101+d.idleNS,false);if d.counters["tcp_idle_expired"]!=1 {t.Fatal(d.counters)}})
    t.Run("fin",func(t *testing.T){d,_:=captureTestDecoder();captureTestTCP(d,100,2,nil,1);captureTestTCP(d,101,0x11,nil,2);if d.counters["tcp_fin_flows"]!=1||d.counters["tcp_incomplete_flows"]!=0 {t.Fatal(d.counters)}})
    t.Run("reset",func(t *testing.T){d,_:=captureTestDecoder();captureTestTCP(d,100,2,nil,1);captureTestTCP(d,101,4,nil,2);if d.counters["tcp_reset_flows"]!=1 {t.Fatal(d.counters)}})
    t.Run("final",func(t *testing.T){d,_:=captureTestDecoder();captureTestTCP(d,100,2,nil,1);captureTestTCP(d,101,0x18,[]byte{0},2);d.expire(0,true);if d.counters["tcp_final_flows"]!=1||d.counters["tcp_incomplete_flows"]!=1 {t.Fatal(d.counters)}})
}

// Tiny interpreter for exactly the classic BPF instructions emitted by our
// filter, to validate offsets/jump targets without requiring CAP_NET_RAW.
func captureTestFilter(frame []byte,port int) uint32 {
    var a,x uint32
    filter:=captureFilter(port)
    for pc:=0;pc<len(filter);pc++ {
        f:=filter[pc]
        read:=func(offset int,size int) uint32 {if offset<0||offset+size>len(frame) {return 0};switch size {case 1:return uint32(frame[offset]);case 2:return uint32(binary.BigEndian.Uint16(frame[offset:offset+2]))};return 0}
        switch f.Code {
        case 0x28:if int(f.K)+2>len(frame) {return 0};a=read(int(f.K),2)
        case 0x30:if int(f.K)+1>len(frame) {return 0};a=read(int(f.K),1)
        case 0xb1:if int(f.K)>=len(frame) {return 0};x=(read(int(f.K),1)&15)*4
        case 0x48:if int(x+f.K)+2>len(frame) {return 0};a=read(int(x+f.K),2)
        case 0x15:if a==f.K {pc+=int(f.Jt)} else {pc+=int(f.Jf)}
        case 0x45:if a&f.K!=0 {pc+=int(f.Jt)} else {pc+=int(f.Jf)}
        case 0x06:return f.K
        default:panic("unexpected BPF instruction")
        }
    }
    return 0
}
func TestCaptureBPFPortProtocolAndFragments(t *testing.T) {
    for _,proto:=range []byte{6,17} {
        if captureTestFilter(captureTestFrame(proto,15363,[]byte{1},1,2),15363)==0 {t.Fatal("correct port rejected",proto)}
        if captureTestFilter(captureTestFrame(proto,53,[]byte{1},1,2),15363)!=0 {t.Fatal("other port accepted",proto)}
    }
    f:=captureTestFrame(17,15363,[]byte{1},0,0);f[20]=0x20
    if captureTestFilter(f,15363)==0 {t.Fatal("fragment not counted")}
    f=captureTestFrame(17,15363,[]byte{1},0,0);f[23]=1
    if captureTestFilter(f,15363)!=0 {t.Fatal("ICMP accepted")}
    if captureTestFilter([]byte{1,2},15363)!=0 {t.Fatal("short packet accepted")}
}
func TestCaptureBPFIPv4Options(t *testing.T) {
    f:=captureTestFrame(17,15363,[]byte{1},0,0)
    f=append(append(append([]byte(nil),f[:34]...),[]byte{0,0,0,0}...),f[34:]...)
    f[14]=0x46;binary.BigEndian.PutUint16(f[16:18],uint16(len(f)-14))
    if captureTestFilter(f,15363)==0 {t.Fatal("IHL-aware port rejected")}
    p,reason:=decodeIPv4Frame(f,15363);if reason!=""||len(p.payload)!=1 {t.Fatalf("%+v %s",p,reason)}
}
func TestCaptureKernelTimestamp(t *testing.T) {
    raw:=make([]byte,syscall.CmsgSpace(int(unsafe.Sizeof(syscall.Timespec{}))))
    header:=(*syscall.Cmsghdr)(unsafe.Pointer(&raw[0]));header.Level=syscall.SOL_SOCKET;header.Type=syscall.SO_TIMESTAMPNS
    header.SetLen(syscall.CmsgLen(int(unsafe.Sizeof(syscall.Timespec{}))))
    ts:=(*syscall.Timespec)(unsafe.Pointer(&raw[syscall.CmsgLen(0)]));ts.Sec=123;ts.Nsec=456
    value,source:=kernelCaptureTimestamp(raw,99)
    if value!=123000000456||source!="kernel_so_timestampns" {t.Fatalf("%d %s",value,source)}
    value,source=kernelCaptureTimestamp(nil,99);if value!=99||source!="receive_wall_fallback" {t.Fatalf("%d %s",value,source)}
}
