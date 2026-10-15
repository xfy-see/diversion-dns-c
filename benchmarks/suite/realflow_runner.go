// realflow_runner consumes the capture helper's JSONL; it never answers production clients.
// Build this file explicitly, separately from the other suite main packages.
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type captureEvent struct {
	Type string `json:"type"`
	TS int64 `json:"ts_unix_ns"`
	Transport string `json:"transport"`
	Wire string `json:"wire_b64"`
	Sequence uint64 `json:"sequence"`
	Packet uint64 `json:"packet_index"`
	Flow string `json:"flow_id"`
}
type question struct { Name string; Type, Class uint16; End int }
type address struct { IP string `json:"ip"`; Family int `json:"family"`; TTL uint32 `json:"ttl"` }
type dnsResult struct {
	Arm string `json:"arm"`
	Endpoint string `json:"endpoint"`
	Transport string `json:"query_transport"`
	QueryID uint16 `json:"query_id"`
	AttemptStartNS int64 `json:"attempt_start_unix_ns"`
	SendStartedNS int64 `json:"send_started_unix_ns"`
	SendStartedMonoNS int64 `json:"send_started_mono_ns"`
	SentNS int64 `json:"sent_unix_ns"`
	SentMonoNS int64 `json:"sent_mono_ns"`
	FinishedMonoNS int64 `json:"finished_mono_ns"`
	WireSent bool `json:"wire_sent"`
	BytesWritten int `json:"bytes_written"`
	TransportResponse bool `json:"transport_response"`
	TimedOut bool `json:"timed_out"`
	LocalAddr string `json:"local_addr,omitempty"`
	SendDelayMS float64 `json:"arrival_to_send_ms"`
	DurationMS float64 `json:"duration_ms"`
	Success bool `json:"success"`
	Error string `json:"error,omitempty"`
	RCODE int `json:"rcode"`
	Truncated bool `json:"truncated"`
	ResponseBytes int `json:"response_bytes"`
	Addresses []address `json:"addresses,omitempty"`
	MinTTL *uint32 `json:"min_answer_ttl,omitempty"`
	Ignored int `json:"ignored_mismatched_responses"`
}
type pairResult struct {
	Kind string `json:"type"`
	Sequence uint64 `json:"sequence"`
	CaptureSequence uint64 `json:"capture_sequence"`
	ArrivalNS int64 `json:"arrival_unix_ns"`
	QuestionID string `json:"question_hmac"`
	QType uint16 `json:"qtype"`
	QClass uint16 `json:"qclass"`
	ProbeHost bool `json:"probe_host"`
	Transport string `json:"query_transport"`
	FirstArm string `json:"first_arm"`
	Disposition string `json:"disposition"`
	BothWireSent bool `json:"both_wire_sent"`
	Reason string `json:"reason,omitempty"`
	A *dnsResult `json:"a,omitempty"`
	B *dnsResult `json:"b,omitempty"`
}
type site struct { Host string `json:"host"`; Path string `json:"path"`; Region string `json:"region"`; Families []int `json:"families"` }
type httpsResult struct {
	Kind string `json:"type"`
	Site site `json:"site"`
	CycleID uint64 `json:"cycle_id"`
	Arm string `json:"arm"`
	Family int `json:"address_family"`
	StartedNS int64 `json:"started_unix_ns"`
	DNS dnsResult `json:"dns"`
	IP string `json:"connected_ip,omitempty"`
	Success bool `json:"success"`
	Error string `json:"error,omitempty"`
	Status int `json:"http_status,omitempty"`
	TCPMS float64 `json:"tcp_ms"`
	TLSMS float64 `json:"tls_ms"`
	TTFBMS float64 `json:"ttfb_ms"`
	HTTPMS float64 `json:"http_total_ms"`
	TotalMS float64 `json:"dns_and_http_total_ms"`
	BodyBytes int64 `json:"body_bytes"`
	BodyLimited bool `json:"body_limited"`
	BodyComplete bool `json:"body_complete"`
	TLSHandshakeSuccess bool `json:"tls_handshake_success"`
	CertificateVerified bool `json:"certificate_verified"`
	Coverage string `json:"coverage"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	LocalAddr string `json:"local_addr,omitempty"`
	BoundInterface string `json:"bound_interface,omitempty"`
	SocketMark uint `json:"socket_mark"`
}

func asciiFold(s string) string {b:=[]byte(s);for i,c:=range b{if c>='A'&&c<='Z'{b[i]=c+('a'-'A')}};return string(b)}

func readName(b []byte, start int) (string, int, error) {
	pos, end, expanded := start, -1, 0
	seen := make(map[int]bool)
	labels := make([]string,0,8)
	for steps:=0;steps<256;steps++ {
		if pos<0||pos>=len(b)||seen[pos] {return "",0,errors.New("bad DNS name offset or cycle")}; seen[pos]=true
		v:=int(b[pos]); pos++
		if v==0 { if end<0 {end=pos}; return asciiFold(strings.Join(labels,".")),end,nil }
		if v&0xc0==0xc0 {if pos>=len(b){return "",0,io.ErrUnexpectedEOF}; target:=((v&0x3f)<<8)|int(b[pos]); if target>=pos-1{return "",0,errors.New("DNS forward pointer")};if end<0{end=pos+1};pos=target;continue}
		if v&0xc0!=0||v>63||pos+v>len(b){return "",0,errors.New("bad DNS label")}
		expanded+=v+1;if expanded>254{return "",0,errors.New("DNS name too long")}
		labels=append(labels,string(b[pos:pos+v]));pos+=v
	}
	return "",0,errors.New("DNS name indirection limit")
}
func parseQuestion(b []byte) (question,error) {
	if len(b)<12||binary.BigEndian.Uint16(b[4:6])!=1{return question{},errors.New("DNS requires one question")}
	n,e,err:=readName(b,12);if err!=nil{return question{},err};if e+4>len(b){return question{},io.ErrUnexpectedEOF}
	return question{n,binary.BigEndian.Uint16(b[e:e+2]),binary.BigEndian.Uint16(b[e+2:e+4]),e+4},nil
}
func parseResponse(query,b []byte) (dnsResult,error) {
	r:=dnsResult{RCODE:-1,ResponseBytes:len(b)}
	if len(query)<12||len(b)<12{return r,io.ErrUnexpectedEOF}
	if b[0]!=query[0]||b[1]!=query[1]||b[2]&0x80==0||b[2]&0x78!=query[2]&0x78{return r,errors.New("DNS ID/QR/opcode mismatch")}
	q,err:=parseQuestion(query);if err!=nil{return r,err};rq,err:=parseQuestion(b);if err!=nil{return r,err}
	if q.Name!=rq.Name||q.Type!=rq.Type||q.Class!=rq.Class{return r,errors.New("DNS question mismatch")}
	r.RCODE=int(b[3]&15);r.Truncated=b[2]&2!=0;pos:=rq.End
	if r.Truncated {r.Error="truncated_response";return r,nil}
	an,ns,ar:=int(binary.BigEndian.Uint16(b[6:8])),int(binary.BigEndian.Uint16(b[8:10])),int(binary.BigEndian.Uint16(b[10:12]))
	if an+ns+ar>len(b)/11{return r,errors.New("impossible DNS record count")}
	for i:=0;i<an+ns+ar;i++ {
		_,end,e:=readName(b,pos);if e!=nil{return r,e};if end+10>len(b){return r,io.ErrUnexpectedEOF}
		typ,cls:=binary.BigEndian.Uint16(b[end:end+2]),binary.BigEndian.Uint16(b[end+2:end+4]);ttl:=binary.BigEndian.Uint32(b[end+4:end+8]);n:=int(binary.BigEndian.Uint16(b[end+8:end+10]));pos=end+10
		if pos+n>len(b){return r,io.ErrUnexpectedEOF}
		if typ==41 {r.RCODE|=int(ttl>>24)<<4}
		if i<an&&cls==1 {if r.MinTTL==nil||ttl<*r.MinTTL{v:=ttl;r.MinTTL=&v};if typ==1&&n==4{r.Addresses=append(r.Addresses,address{net.IP(b[pos:pos+n]).String(),4,ttl})};if typ==28&&n==16{r.Addresses=append(r.Addresses,address{net.IP(b[pos:pos+n]).String(),6,ttl})}}
		pos+=n
	}
	if pos!=len(b){return r,errors.New("trailing DNS response bytes")}
	r.Success=r.RCODE==0||r.RCODE==3
	if !r.Success{r.Error=fmt.Sprintf("dns_rcode_%d",r.RCODE)}
	return r,nil
}
func runnerMonotonicNS()int64{var ts syscall.Timespec;_,_,errno:=syscall.Syscall(syscall.SYS_CLOCK_GETTIME,1,uintptr(unsafe.Pointer(&ts)),0);if errno!=0{return 0};return int64(ts.Sec)*1e9+int64(ts.Nsec)}
func dnsQuery(ctx context.Context,endpoint,arm,transport string,wire []byte,arrival int64,timeout time.Duration) dnsResult {
	start:=time.Now();r:=dnsResult{Arm:arm,Endpoint:endpoint,Transport:transport,AttemptStartNS:start.UnixNano(),RCODE:-1};if len(wire)>=2{r.QueryID=binary.BigEndian.Uint16(wire[:2])}
	finish:=func(e error) dnsResult {r.DurationMS=float64(time.Since(start))/float64(time.Millisecond);r.FinishedMonoNS=runnerMonotonicNS();if e!=nil{r.Success=false;r.Error=e.Error();var ne net.Error;if errors.As(e,&ne)&&ne.Timeout(){r.TimedOut=true};if errors.Is(e,context.DeadlineExceeded){r.TimedOut=true}};return r}
	accept:=func(p dnsResult){r.Success=p.Success;r.Error=p.Error;r.RCODE=p.RCODE;r.Truncated=p.Truncated;r.ResponseBytes=p.ResponseBytes;r.Addresses=p.Addresses;r.MinTTL=p.MinTTL;r.TransportResponse=true}
	markSent:=func(){r.WireSent=true;r.SentNS=time.Now().UnixNano();r.SentMonoNS=runnerMonotonicNS();r.SendDelayMS=float64(r.SentNS-arrival)/1e6}
	if transport!="udp"&&transport!="tcp"{return finish(errors.New("unsupported query transport"))}
	requestCtx,cancel:=context.WithTimeout(ctx,timeout);defer cancel()
	dial:=net.Dialer{};conn,err:=dial.DialContext(requestCtx,transport,endpoint);if err!=nil{return finish(err)};defer conn.Close();r.LocalAddr=conn.LocalAddr().String()
	deadline,_:=requestCtx.Deadline();if err=conn.SetDeadline(deadline);err!=nil{return finish(err)}
	if transport=="tcp" {
		if len(wire)>65535{return finish(errors.New("DNS request too large"))};framed:=make([]byte,len(wire)+2);binary.BigEndian.PutUint16(framed,uint16(len(wire)));copy(framed[2:],wire);r.SendStartedNS=time.Now().UnixNano();r.SendStartedMonoNS=runnerMonotonicNS()
		for len(framed)>0 {n,e:=conn.Write(framed);r.BytesWritten+=n;if e!=nil{return finish(e)};if n==0{return finish(io.ErrShortWrite)};framed=framed[n:]};markSent()
		h:=make([]byte,2);if _,err=io.ReadFull(conn,h);err!=nil{return finish(err)};response:=make([]byte,int(binary.BigEndian.Uint16(h)));if _,err=io.ReadFull(conn,response);err!=nil{return finish(err)}
		parsed,e:=parseResponse(wire,response);if e!=nil{return finish(e)};accept(parsed);return finish(nil)
	}
	r.SendStartedNS=time.Now().UnixNano();r.SendStartedMonoNS=runnerMonotonicNS();n,err:=conn.Write(wire);r.BytesWritten=n;if err!=nil{return finish(err)};if n!=len(wire){return finish(io.ErrShortWrite)};markSent()
	buf:=make([]byte,65535)
	for {n,e:=conn.Read(buf);if e!=nil{return finish(e)};parsed,e:=parseResponse(wire,buf[:n]);if e!=nil{r.Ignored++;if r.Ignored>=32{return finish(fmt.Errorf("too many invalid responses: %w",e))};continue};accept(parsed);return finish(nil)}
}
func makeQuery(host string,typ uint16) []byte {
	b:=make([]byte,12);rand.Read(b[:2]);b[2]=1;b[5]=1
	if host!="" {for _,l:=range strings.Split(host,"."){b=append(b,byte(len(l)));b=append(b,[]byte(l)...)} };b=append(b,0,byte(typ>>8),byte(typ),0,1);return b
}
func validSite(s site) error {
	if s.Host==""||len(s.Host)>253||net.ParseIP(s.Host)!=nil||strings.TrimSpace(s.Host)!=s.Host{return errors.New("site host must be a DNS hostname")}
	for _,l:=range strings.Split(s.Host,"."){if len(l)==0||len(l)>63||l[0]=='-'||l[len(l)-1]=='-'{return errors.New("bad site hostname label")};for _,c:=range l{if !(c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='-'){return errors.New("bad site hostname character")}}}
	u,e:=url.ParseRequestURI(s.Path);if e!=nil||!strings.HasPrefix(s.Path,"/")||strings.HasPrefix(s.Path,"//")||u.IsAbs()||u.Host!=""||u.Fragment!=""{return errors.New("site path must be an absolute path without authority")}
	if len(s.Families)==0{return errors.New("site has no families")};for _,f:=range s.Families{if f!=4&&f!=6{return errors.New("site family must be 4 or 6")}}
	return nil
}
type httpsConfig struct {Roots *x509.CertPool; Interface string; Mark uint; Port string}
func doHTTPS(ctx context.Context,s site,ip string,bodyLimit int64,cfg httpsConfig) httpsResult {
	r:=httpsResult{Kind:"https_probe",Site:s,IP:ip,BoundInterface:cfg.Interface,SocketMark:cfg.Mark};start:=time.Now()
	if e:=validSite(s);e!=nil{r.Error=e.Error();return r};p:=net.ParseIP(ip);if p==nil{r.Error="invalid fixed destination IP";return r}
	var tcpStart,tlsStart time.Time;var traceMu sync.Mutex
	trace:=&httptrace.ClientTrace{ConnectStart:func(_, _ string){traceMu.Lock();tcpStart=time.Now();traceMu.Unlock()},ConnectDone:func(_, _ string,_ error){traceMu.Lock();r.TCPMS=float64(time.Since(tcpStart))/1e6;traceMu.Unlock()},TLSHandshakeStart:func(){traceMu.Lock();tlsStart=time.Now();traceMu.Unlock()},TLSHandshakeDone:func(state tls.ConnectionState,err error){traceMu.Lock();r.TLSMS=float64(time.Since(tlsStart))/1e6;r.TLSHandshakeSuccess=err==nil;r.CertificateVerified=err==nil&&len(state.VerifiedChains)>0;traceMu.Unlock()},GotFirstResponseByte:func(){traceMu.Lock();r.TTFBMS=float64(time.Since(start))/1e6;traceMu.Unlock()},GotConn:func(i httptrace.GotConnInfo){traceMu.Lock();r.RemoteAddr=i.Conn.RemoteAddr().String();r.LocalAddr=i.Conn.LocalAddr().String();traceMu.Unlock()}}
	dial:=&net.Dialer{Timeout:5*time.Second}
	if cfg.Interface!=""||cfg.Mark!=0{dial.Control=func(_, _ string,raw syscall.RawConn)error{var socketErr error;err:=raw.Control(func(fd uintptr){if cfg.Interface!=""{socketErr=syscall.SetsockoptString(int(fd),syscall.SOL_SOCKET,syscall.SO_BINDTODEVICE,cfg.Interface)};if socketErr==nil&&cfg.Mark!=0{socketErr=syscall.SetsockoptInt(int(fd),syscall.SOL_SOCKET,syscall.SO_MARK,int(cfg.Mark))}});if err!=nil{return err};return socketErr}}
	port:=cfg.Port;if port==""{port="443"}
	transport:=&http.Transport{Proxy:nil,DisableKeepAlives:true,ForceAttemptHTTP2:false,TLSNextProto:map[string]func(string,*tls.Conn)http.RoundTripper{},TLSClientConfig:&tls.Config{ServerName:s.Host,MinVersion:tls.VersionTLS12,RootCAs:cfg.Roots},DialContext:func(c context.Context,network,_ string)(net.Conn,error){return dial.DialContext(c,network,net.JoinHostPort(ip,port))},TLSHandshakeTimeout:5*time.Second,ResponseHeaderTimeout:10*time.Second}
	defer transport.CloseIdleConnections();client:=&http.Client{Transport:transport,Timeout:20*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}
	req,e:=http.NewRequestWithContext(httptrace.WithClientTrace(ctx,trace),"GET","https://"+s.Host+s.Path,nil);if e!=nil{r.Error=e.Error();return r};req.Host=s.Host;req.Header.Set("User-Agent","diversion-dns-realflow-validation/1");req.Header.Set("Accept-Encoding","identity")
	response,e:=client.Do(req);if e!=nil{r.Error=e.Error();r.HTTPMS=float64(time.Since(start))/1e6;return r};defer response.Body.Close();r.Status=response.StatusCode
	n,e:=io.Copy(io.Discard,io.LimitReader(response.Body,bodyLimit+1));r.BodyLimited=n>bodyLimit;r.BodyComplete=!r.BodyLimited&&e==nil;if n>bodyLimit{n=bodyLimit};r.BodyBytes=n;r.HTTPMS=float64(time.Since(start))/1e6
	if e!=nil{r.Error=e.Error()}else if r.Status<200||r.Status>=400{r.Error=fmt.Sprintf("http_status_%d",r.Status)}else{r.Success=true};return r
}

// Histogram bins are upper bounds: 0.1ms through 1s, 1ms through 10s,
// 100ms through 100s, then 1s. Percentiles are bounded approximations; max is exact.
type histogram struct { Count uint64 `json:"count"`; Sum float64 `json:"sum_ms"`; Max float64 `json:"max_ms"`; Bins map[int]uint64 `json:"-"` }
func bucket(v float64) int {if v<=1000{return int(math.Ceil(v*10))};if v<=10000{return 10000+int(math.Ceil(v-1000))};if v<=100000{return 19000+int(math.Ceil((v-10000)/100))};return 19900+int(math.Ceil((v-100000)/1000))}
func bound(k int) float64 {if k<=10000{return float64(k)/10};if k<=19000{return 1000+float64(k-10000)};if k<=19900{return 10000+float64(k-19000)*100};return 100000+float64(k-19900)*1000}
func(h *histogram)add(v float64){if h.Bins==nil{h.Bins=make(map[int]uint64)};h.Count++;h.Sum+=v;if v>h.Max{h.Max=v};h.Bins[bucket(v)]++}
func(h *histogram)summary()map[string]any {r:=map[string]any{"count":h.Count,"max_ms":h.Max,"percentile_method":"histogram_upper_bound_0.1ms_then_1ms_then_100ms","p99_sample_sufficient":h.Count>=1000};if h.Count==0{return r};r["mean_ms"]=h.Sum/float64(h.Count);keys:=make([]int,0,len(h.Bins));for k:=range h.Bins{keys=append(keys,k)};sort.Ints(keys);for _,p:=range []float64{50,90,99}{target:=uint64(math.Ceil(float64(h.Count)*p/100));var n uint64;for _,k:=range keys{n+=h.Bins[k];if n>=target{r["p"+strconv.Itoa(int(p))+"_ms"]=bound(k);break}}};return r}
type armStats struct { Attempted uint64 `json:"attempted"`;Sent uint64 `json:"sent"`;Responses uint64 `json:"transport_responses"`;Successful uint64 `json:"successful"`; Failed uint64 `json:"failed"`; Timeouts uint64 `json:"timeouts"`; RCodes map[int]uint64 `json:"rcodes"`; SuccessLatency histogram `json:"-"`; AllLatency histogram `json:"-"`; SendDelay histogram `json:"-"` }
func(a *armStats)add(r dnsResult){a.Attempted++;if r.WireSent{a.Sent++;a.SendDelay.add(math.Max(0,r.SendDelayMS))};if r.TransportResponse{a.Responses++;if a.RCodes==nil{a.RCodes=make(map[int]uint64)};a.RCodes[r.RCODE]++};a.AllLatency.add(r.DurationMS);if r.Success{a.Successful++;a.SuccessLatency.add(r.DurationMS)}else{a.Failed++;if r.TimedOut{a.Timeouts++}}}
func(a *armStats)view()map[string]any {return map[string]any{"attempted":a.Attempted,"sent":a.Sent,"transport_responses":a.Responses,"successful":a.Successful,"failed":a.Failed,"timeouts":a.Timeouts,"rcodes":a.RCodes,"success_latency":a.SuccessLatency.summary(),"all_latency":a.AllLatency.summary(),"arrival_to_send":a.SendDelay.summary()}}
type stats struct { Arrivals uint64; Accepted uint64; Unsent uint64; Invalid uint64; Reasons map[string]uint64; A,B armStats }
func(s *stats)add(p pairResult){s.Arrivals++;if p.Disposition=="sent"{s.Accepted++;s.A.add(*p.A);s.B.add(*p.B)}else{s.Unsent++;if p.Disposition=="invalid"{s.Invalid++};if s.Reasons==nil{s.Reasons=make(map[string]uint64)};s.Reasons[p.Reason]++}}
func(s *stats)view()map[string]any{return map[string]any{"arrivals":s.Arrivals,"accepted_pairs":s.Accepted,"unsent_pairs":s.Unsent,"invalid":s.Invalid,"unsent_reasons":s.Reasons,"a":s.A.view(),"b":s.B.view()}}
type writer struct {mu sync.Mutex;f *os.File;err error;closed bool}
func(w *writer)write(v any){w.mu.Lock();defer w.mu.Unlock();if w.err!=nil{return};b,e:=json.Marshal(v);if e==nil{_,e=w.f.Write(append(b,'\n'))};if e!=nil{w.err=e}}
func(w *writer)close()error{w.mu.Lock();defer w.mu.Unlock();if w.closed{return w.err};w.closed=true;e:=w.f.Sync();ce:=w.f.Close();if w.err==nil{w.err=e};if w.err==nil{w.err=ce};return w.err}
func privateFile(dir,name string)(*writer,error){f,e:=os.OpenFile(filepath.Join(dir,name),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if e!=nil{return nil,e};return &writer{f:f},nil}
func atomicJSON(dir,name string,v any)error{b,e:=json.MarshalIndent(v,"","  ");if e!=nil{return e};f,e:=os.CreateTemp(dir,".state-");if e!=nil{return e};tmp:=f.Name();defer os.Remove(tmp);if e=f.Chmod(0600);e==nil{_,e=f.Write(append(b,'\n'))};if e==nil{e=f.Sync()};ce:=f.Close();if e==nil{e=ce};if e!=nil{return e};return os.Rename(tmp,filepath.Join(dir,name))}
type work struct { event captureEvent; wire []byte; q question; index uint64 }
type options struct {A,B,Output,Sites,HTTPSInterface string;HTTPSMark uint;Duration,Timeout,HTTPSInterval time.Duration;MaxInflight,Queue int;BodyLimit int64;Fixture bool}

func run(ctx context.Context,opts options,input io.Reader) error {
	if opts.Duration<=0||opts.Timeout<=0||opts.MaxInflight<1||opts.MaxInflight>256||opts.Queue<1||opts.Queue>65536{return errors.New("invalid duration/timeout/concurrency/queue")}
	if opts.BodyLimit<1||opts.BodyLimit>1024*1024{return errors.New("body limit must be 1..1048576")}
	if opts.HTTPSMark>0xffffffff||len(opts.HTTPSInterface)>15||strings.ContainsAny(opts.HTTPSInterface,"/\x00 \t\r\n"){return errors.New("invalid HTTPS interface or mark")}
	for _,v:=range []string{opts.A,opts.B}{if _,_,e:=net.SplitHostPort(v);e!=nil{return fmt.Errorf("bad DNS endpoint: %w",e)}}
	var sites []site;if opts.Sites!=""{b,e:=os.ReadFile(opts.Sites);if e!=nil{return e};if e=json.Unmarshal(b,&sites);e!=nil{return e};if len(sites)>32{return errors.New("at most 32 HTTPS sites")};for _,s:=range sites{if e=validSite(s);e!=nil{return e}};if opts.HTTPSInterval<time.Second{return errors.New("HTTPS interval must be at least one second")}}
	if err:=os.Mkdir(opts.Output,0700);err!=nil{return fmt.Errorf("output must be a new private directory: %w",err)}
	key:=make([]byte,32);if _,e:=rand.Read(key);e!=nil{return e};if e:=os.WriteFile(filepath.Join(opts.Output,"hmac.key"),key,0600);e!=nil{return e}
	results,e:=privateFile(opts.Output,"dns-results.jsonl");if e!=nil{return e};defer results.close();capture,e:=privateFile(opts.Output,"capture-private.jsonl");if e!=nil{return e};defer capture.close();windows,e:=privateFile(opts.Output,"windows.jsonl");if e!=nil{return e};defer windows.close();httpsLog,e:=privateFile(opts.Output,"https-results.jsonl");if e!=nil{return e};defer httpsLog.close()
	started:=time.Now();startedMono:=runnerMonotonicNS();deadline:=started.Add(opts.Duration)
	probeHosts:=make(map[string]bool);for _,s:=range sites{probeHosts[strings.ToLower(s.Host)]=true}
	metadata:=map[string]any{"schema":1,"start_unix_ns":started.UnixNano(),"expected_end_unix_ns":deadline.UnixNano(),"a":opts.A,"b":opts.B,"duration_seconds":opts.Duration.Seconds(),"max_pair_inflight":opts.MaxInflight,"queue_pairs":opts.Queue,"dns_timeout_seconds":opts.Timeout.Seconds(),"https_sites":sites,"probe_hosts":probeHosts,"https_interface":opts.HTTPSInterface,"https_mark":opts.HTTPSMark,"https_first_probe_after_seconds":opts.HTTPSInterval.Seconds(),"https_interval_seconds":opts.HTTPSInterval.Seconds(),"https_body_limit":opts.BodyLimit,"https_scope":"fixed-IP certificate-verified HTTP GET, no environment proxy, no redirect, bounded body prefix; not browser rendering or necessarily a complete response","tcp_scope":"each mirrored DNS query uses a fresh TCP connection; original persistent client flow is not reproduced","classification_counters":"cache split counters supplied by external server stderr; unavailable on baseline if unsupported","raw_data_privacy":"all files mode0600; capture-private.jsonl contains original DNS wire; names in results are HMAC IDs"}
	metadata["disposition_sent_semantics"]="dispatched pair: both arms attempted; actual per-arm transmission requires wire_sent=true; bytes_written includes the 2-byte TCP length prefix"
	metadata["start_mono_ns"]=startedMono
	metadata["timestamp_semantics"]="send_started_mono_ns is Linux CLOCK_MONOTONIC immediately before Write; sent_mono_ns and sent_unix_ns follow successful complete wire write; finished_mono_ns is result completion; arrival_to_send_ms ends after full write"
	metadata["window_assignment"]="online windows group by result completion time; original arrival_unix_ns retained for exact offline arrival-window regrouping"
	if e=atomicJSON(opts.Output,"metadata.json",metadata);e!=nil{return e}
	var mu sync.Mutex;var total,current stats;var lastCapture any;var captureFinal bool;complete:=true;reasons:=make(map[string]bool);var arrivalCount uint64;var lastSequence uint64;var stateError error
	windowStart:=started
	record:=func(p pairResult){results.write(p);mu.Lock();total.add(p);current.add(p);mu.Unlock()}
	markIncomplete:=func(reason string){mu.Lock();complete=false;reasons[reason]=true;mu.Unlock()}
	identity:=func(q question)string{mac:=hmac.New(sha256.New,key);fmt.Fprintf(mac,"%s\x00%d\x00%d",q.Name,q.Type,q.Class);return hex.EncodeToString(mac.Sum(nil))}
	basePair:=func(w work)pairResult{first:="a";if w.index%2==0{first="b"};return pairResult{Kind:"dns_mirror",Sequence:w.index,CaptureSequence:w.event.Sequence,ArrivalNS:w.event.TS,QuestionID:identity(w.q),QType:w.q.Type,QClass:w.q.Class,ProbeHost:probeHosts[w.q.Name],Transport:w.event.Transport,FirstArm:first}}
	queue:=make(chan work,opts.Queue);var workers sync.WaitGroup
	for i:=0;i<opts.MaxInflight;i++{workers.Add(1);go func(){defer workers.Done();for w:=range queue{p:=basePair(w);p.Disposition="sent";ch:=make(chan dnsResult,2);send:=func(arm,endpoint string){go func(){ch<-dnsQuery(ctx,endpoint,arm,w.event.Transport,w.wire,w.event.TS,opts.Timeout)}()};if p.FirstArm=="a"{send("a",opts.A);send("b",opts.B)}else{send("b",opts.B);send("a",opts.A)};for j:=0;j<2;j++{r:=<-ch;if r.Arm=="a"{p.A=&r}else{p.B=&r}};p.BothWireSent=p.A.WireSent&&p.B.WireSent;record(p)}}()}
	inputLines:=make(chan []byte,64);inputDone:=make(chan error,1);readerStop:=make(chan struct{})
	go func(){defer close(inputLines);sc:=bufio.NewScanner(input);sc.Buffer(make([]byte,65536),1024*1024);for sc.Scan(){line:=append([]byte(nil),sc.Bytes()...);select{case inputLines<-line:case <-readerStop:return}};inputDone<-sc.Err()}()
	var probes sync.WaitGroup;probeCtx,cancelProbes:=context.WithCancel(ctx);defer cancelProbes()
	if len(sites)>0{probes.Add(1);go func(){defer probes.Done();tick:=time.NewTicker(opts.HTTPSInterval);defer tick.Stop();cycle:=uint64(0);for{select{case<-probeCtx.Done():return;case<-tick.C:};for _,s:=range sites{for _,family:=range s.Families{arms:=[]string{"a","b"};if cycle%2==1{arms=[]string{"b","a"}};for _,arm:=range arms{select{case <-probeCtx.Done():return;default:};endpoint:=opts.A;if arm=="b"{endpoint=opts.B};typ:=uint16(1);if family==6{typ=28};beg:=time.Now();dr:=dnsQuery(probeCtx,endpoint,arm,"udp",makeQuery(s.Host,typ),beg.UnixNano(),opts.Timeout);hr:=httpsResult{Kind:"https_probe",Site:s,Arm:arm,Family:family,StartedNS:beg.UnixNano(),DNS:dr,Coverage:"attempted",BoundInterface:opts.HTTPSInterface,SocketMark:opts.HTTPSMark};if !dr.Success{hr.Error="dns: "+dr.Error}else{ip:="";for _,a:=range dr.Addresses{if a.Family==family{ip=a.IP;break}};if ip==""{hr.Error="dns_no_address_for_family";hr.Coverage="uncovered_no_address"}else{hr=doHTTPS(probeCtx,s,ip,opts.BodyLimit,httpsConfig{Interface:opts.HTTPSInterface,Mark:opts.HTTPSMark});hr.Coverage="attempted";hr.Arm=arm;hr.Family=family;hr.StartedNS=beg.UnixNano();hr.DNS=dr}};hr.CycleID=cycle+1;hr.TotalMS=float64(time.Since(beg))/1e6;httpsLog.write(hr)}}};cycle++}}()}
	snapshot:=func(final bool){mu.Lock();defer mu.Unlock();now:=time.Now();rs:=make([]string,0,len(reasons));for r:=range reasons{rs=append(rs,r)};sort.Strings(rs);v:=map[string]any{"schema":1,"start_unix_ns":started.UnixNano(),"observed_unix_ns":now.UnixNano(),"expected_end_unix_ns":deadline.UnixNano(),"elapsed_seconds":now.Sub(started).Seconds(),"complete":complete,"incomplete_reasons":rs,"input_queries":arrivalCount,"results":total.view(),"last_capture_stats":lastCapture,"capture_final_stats_seen":captureFinal,"finished":final,"queue_pairs":len(queue),"https_results_file":"https-results.jsonl"};if err:=atomicJSON(opts.Output,"status.json",v);err!=nil{stateError=err};if final{if err:=atomicJSON(opts.Output,"final.json",v);err!=nil{stateError=err}}else if now.Sub(windowStart)>=15*time.Minute{windows.write(map[string]any{"type":"window","start_unix_ns":windowStart.UnixNano(),"end_unix_ns":now.UnixNano(),"complete":complete,"results":current.view(),"last_capture_stats":lastCapture});current=stats{};windowStart=now}}
	snapshot(false)
	timer:=time.NewTimer(opts.Duration);defer timer.Stop();statusTick:=time.NewTicker(15*time.Second);defer statusTick.Stop();var terminal error;var grace <-chan time.Time;var graceTimer *time.Timer;pastDeadline:=false
	loop:for{select{
	case <-ctx.Done():markIncomplete("runner_cancelled");terminal=ctx.Err();break loop
	case <-timer.C:pastDeadline=true;cancelProbes();graceTimer=time.NewTimer(5*time.Second);grace=graceTimer.C
	case <-grace:if !captureFinal{markIncomplete("capture_final_stats_unavailable")};break loop
	case <-statusTick.C:snapshot(false)
	case line,ok:=<-inputLines:
		if !ok{if time.Now().Before(deadline){markIncomplete("capture_eof_before_deadline")};terminal=<-inputDone;break loop}
		var ev captureEvent;if err:=json.Unmarshal(line,&ev);err!=nil{capture.write(map[string]any{"type":"invalid_capture_json","line":string(line),"error":err.Error()});markIncomplete("invalid_capture_json");continue}
		var raw any;if json.Unmarshal(line,&raw)==nil{capture.write(json.RawMessage(line))}
		if ev.Type=="capture_stats"||ev.Type=="capture_end"{mu.Lock();lastCapture=raw;mu.Unlock();var st struct{Final bool `json:"final"`;KernelDrops uint64 `json:"kernel_drops"`;Counters map[string]uint64 `json:"counters"`};if json.Unmarshal(line,&st)==nil{if st.Final{captureFinal=true};if st.KernelDrops>0{markIncomplete("capture_kernel_drops")};for k,v:=range st.Counters{if v>0&&(strings.Contains(k,"queue_full")||strings.Contains(k,"incomplete")||strings.Contains(k,"without_syn_payload")||strings.Contains(k,"gap_or_pending_limit")||strings.Contains(k,"buffer_limit")||strings.Contains(k,"flow_limit_evicted")||strings.Contains(k,"conflicting_overlap")||strings.Contains(k,"fragment")||k=="socket_truncated"||k=="recv_failed"||k=="packet_statistics_failed"||k=="json_encode_failed"||k=="dns_question_parse_failed"){markIncomplete("capture_"+k)}}};if pastDeadline&&captureFinal{break loop};continue};if ev.Type!="dns_query"{continue};if pastDeadline&&ev.TS>deadline.UnixNano(){continue}
		mu.Lock();arrivalCount++;index:=arrivalCount;mu.Unlock()
		if ev.Sequence!=0{if lastSequence!=0&&ev.Sequence!=lastSequence+1{markIncomplete("capture_query_sequence_gap")};lastSequence=ev.Sequence}
		wire,err:=base64.StdEncoding.DecodeString(ev.Wire);q,qerr:=parseQuestion(wire);w:=work{ev,wire,q,index};p:=basePair(w)
		if err!=nil||qerr!=nil||ev.TS<=0||(ev.Transport!="udp"&&ev.Transport!="tcp")||len(wire)>65535||(len(wire)>=3&&wire[2]&0x80!=0){p.Disposition="invalid";p.Reason="invalid_capture_query";record(p);markIncomplete(p.Reason);continue}
		select{case queue<-w:default:p.Disposition="unsent";p.Reason="pair_queue_full";record(p);markIncomplete(p.Reason)}
	}}
	if graceTimer!=nil{graceTimer.Stop()};close(readerStop);close(queue);cancelProbes();workers.Wait();probes.Wait();if !captureFinal{markIncomplete("capture_final_stats_unavailable")}
	mu.Lock();windows.write(map[string]any{"type":"window","start_unix_ns":windowStart.UnixNano(),"end_unix_ns":time.Now().UnixNano(),"partial_window":true,"complete":complete,"results":current.view(),"last_capture_stats":lastCapture});mu.Unlock();snapshot(true)
	for _,w:=range []*writer{results,capture,windows,httpsLog}{if err:=w.close();err!=nil{markIncomplete("evidence_write_failed");snapshot(true);return fmt.Errorf("evidence write failed: %w",err)}}
	if stateError!=nil{return fmt.Errorf("state write failed: %w",stateError)}
	return terminal
}

func fixtureSmoke()error{
	udp,e:=net.ListenPacket("udp","127.0.0.1:0");if e!=nil{return e};defer udp.Close();port:=udp.LocalAddr().(*net.UDPAddr).Port;tcp,e:=net.Listen("tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(port)));if e!=nil{return e};defer tcp.Close()
	answer:=func(q []byte)[]byte{r:=append([]byte(nil),q...);r[2]=0x81;r[3]=0x80;return r}
	go func(){b:=make([]byte,65535);for{n,a,e:=udp.ReadFrom(b);if e!=nil{return};udp.WriteTo(answer(b[:n]),a)}}()
	go func(){for{c,e:=tcp.Accept();if e!=nil{return};go func(){defer c.Close();h:=make([]byte,2);if _,e:=io.ReadFull(c,h);e!=nil{return};b:=make([]byte,int(binary.BigEndian.Uint16(h)));if _,e:=io.ReadFull(c,b);e!=nil{return};r:=answer(b);binary.BigEndian.PutUint16(h,uint16(len(r)));c.Write(append(h,r...))}()}}()
	dir,e:=os.MkdirTemp("","realflow-smoke-");if e!=nil{return e};defer os.RemoveAll(dir);pr,pw:=io.Pipe()
	go func(){defer pw.Close();for i:=0;i<8;i++{transport:="udp";if i%2==1{transport="tcp"};json.NewEncoder(pw).Encode(captureEvent{Type:"dns_query",TS:time.Now().UnixNano(),Transport:transport,Wire:base64.StdEncoding.EncodeToString(makeQuery("example.com",1)),Sequence:uint64(i+1)})};time.Sleep(500*time.Millisecond)}()
	e=run(context.Background(),options{A:udp.LocalAddr().String(),B:udp.LocalAddr().String(),Output:filepath.Join(dir,"results"),Duration:2*time.Second,Timeout:time.Second,MaxInflight:2,Queue:16,BodyLimit:1024},pr);if e!=nil{return e};b,e:=os.ReadFile(filepath.Join(dir,"results","final.json"));if e!=nil{return e};var d struct{Results struct{Accepted uint64 `json:"accepted_pairs"`;A struct{Success uint64 `json:"successful"`} `json:"a"`;B struct{Success uint64 `json:"successful"`} `json:"b"`} `json:"results"`};if e=json.Unmarshal(b,&d);e!=nil{return e};if d.Results.Accepted!=8||d.Results.A.Success!=8||d.Results.B.Success!=8{return fmt.Errorf("fixture smoke incomplete: %s",b)};fmt.Println("realflow fixture smoke: 8 pairs / 16 DNS replies, UDP+TCP PASS");return nil
}
func main(){var o options;var seconds,timeout,interval int
	flag.StringVar(&o.A,"a","127.0.0.1:15461","baseline DNS endpoint");flag.StringVar(&o.B,"b","127.0.0.1:15462","candidate DNS endpoint");flag.StringVar(&o.Output,"output","","new private evidence directory");flag.StringVar(&o.Sites,"sites","","HTTPS sites JSON");flag.StringVar(&o.HTTPSInterface,"https-interface","","bind HTTPS sockets to this Linux interface; failure is fatal for that probe");flag.UintVar(&o.HTTPSMark,"https-mark",0,"SO_MARK on HTTPS sockets");flag.IntVar(&seconds,"duration",86400,"observation seconds");flag.IntVar(&timeout,"dns-timeout",5,"DNS timeout seconds");flag.IntVar(&interval,"https-interval",900,"HTTPS cycle seconds");flag.IntVar(&o.MaxInflight,"max-inflight",64,"concurrent mirrored pairs");flag.IntVar(&o.Queue,"queue",1024,"queued pairs");flag.Int64Var(&o.BodyLimit,"body-limit",65536,"maximum HTTP body bytes per request");flag.BoolVar(&o.Fixture,"fixture-smoke",false,"run short localhost fixture and exit");flag.Parse()
	if o.Fixture{if e:=fixtureSmoke();e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)};return};if o.Output==""{fmt.Fprintln(os.Stderr,"-output required");os.Exit(2)};o.Duration=time.Duration(seconds)*time.Second;o.Timeout=time.Duration(timeout)*time.Second;o.HTTPSInterval=time.Duration(interval)*time.Second
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop();if e:=run(ctx,o,os.Stdin);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
}
