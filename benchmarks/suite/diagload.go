// Diagnostic fixed-arrival client for tail-latency attribution; compile only in GitHub Actions.
// It reproduces the load.go workload (same names, IDs, types, cold cookie, -unique) but records
// per-request CLOCK_MONOTONIC timestamps (scheduled slot, worker pickup/send, receive, TCP connect)
// so they can be joined with the server's DIVERSION_TRACE file. Unlike load.go it allows larger
// worker pools and optional pre-dialing; results are diagnostic only and never replace load.go
// pass criteria.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var order = binary.BigEndian

type job struct {
	I  int
	At time.Time
}

// Sample times are CLOCK_MONOTONIC nanoseconds (same clock as the server trace); 0 = not reached.
type Sample struct {
	I         int    `json:"i"`
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Type      int    `json:"type"`
	Worker    int    `json:"worker"`
	Slot      int64  `json:"slot_ns"`
	Pickup    int64  `json:"pickup_ns"`
	Connect0  int64  `json:"connect0_ns,omitempty"`
	Connect1  int64  `json:"connect1_ns,omitempty"`
	Send      int64  `json:"send_ns"`
	Recv      int64  `json:"recv_ns"`
	Unsent    string `json:"unsent,omitempty"`
	Error     string `json:"error,omitempty"`
	ConnFirst bool   `json:"conn_first,omitempty"`
}

var baseWall time.Time
var baseMono int64

func clockMonotonic() int64 {
	var ts syscall.Timespec
	// CLOCK_MONOTONIC = 1
	if _, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0); e != 0 {
		panic(e)
	}
	return int64(ts.Sec)*1e9 + int64(ts.Nsec)
}

// Go's monotonic reading is CLOCK_MONOTONIC on Linux; map it once instead of a syscall per stamp.
func mono(t time.Time) int64 { return baseMono + int64(t.Sub(baseWall)) }

func u16(b []byte, n int) int { return int(order.Uint16(b[n : n+2])) }
func skip(b []byte, p int) (int, error) {
	for i := 0; i < 128; i++ {
		if p >= len(b) {
			break
		}
		v := int(b[p])
		p++
		if v == 0 {
			return p, nil
		}
		if v&192 == 192 {
			if p < len(b) {
				return p + 1, nil
			}
			break
		}
		if v > 63 || p+v > len(b) {
			break
		}
		p += v
	}
	return 0, fmt.Errorf("invalid name")
}

// valid is identical to load.go's acceptance rule.
func valid(q, r []byte, typ int) error {
	if len(r) < 12 || u16(r, 0) != u16(q, 0) || u16(r, 2)&0x8000 == 0 {
		return fmt.Errorf("header")
	}
	if u16(r, 2)&15 != 0 {
		return fmt.Errorf("rcode_%d", u16(r, 2)&15)
	}
	if u16(r, 2)&512 != 0 {
		return fmt.Errorf("truncated")
	}
	if u16(r, 4) != 1 {
		return fmt.Errorf("questions")
	}
	p, e := skip(r, 12)
	if e != nil || p+4 > len(r) {
		return fmt.Errorf("question")
	}
	end, _ := skip(q, 12)
	if string(r[12:p+4]) != string(q[12:end+4]) {
		return fmt.Errorf("question_mismatch")
	}
	p += 4
	found := false
	for j := 0; j < u16(r, 6); j++ {
		p, e = skip(r, p)
		if e != nil || p+10 > len(r) {
			return fmt.Errorf("rr")
		}
		t := u16(r, p)
		cl := u16(r, p+2)
		l := u16(r, p+8)
		p += 10
		if p+l > len(r) {
			return fmt.Errorf("rdata")
		}
		if t == typ && cl == 1 && ((t == 1 && l == 4) || (t == 28 && l == 16)) {
			found = true
		}
		p += l
	}
	if !found {
		return fmt.Errorf("no_address_answer")
	}
	return nil
}

func query(id int, name string, typ int, cold bool) []byte {
	b := make([]byte, 12)
	order.PutUint16(b, uint16(id))
	order.PutUint16(b[2:], 256)
	order.PutUint16(b[4:], 1)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, []byte(l)...)
	}
	b = append(b, 0, byte(typ>>8), byte(typ), 0, 1)
	if cold {
		order.PutUint16(b[10:], 1)
		b = append(b, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8)
		cookie := make([]byte, 8)
		order.PutUint64(cookie, uint64(time.Now().UnixNano())^uint64(id))
		b = append(b, cookie...)
	}
	return b
}

func main() {
	addr := flag.String("addr", "127.0.0.1:53", "")
	network := flag.String("net", "udp", "")
	rate := flag.Int("rate", 50, "")
	seconds := flag.Int("seconds", 20, "")
	workers := flag.Int("workers", 32, "")
	predial := flag.Bool("predial", false, "dial every worker connection before the first slot")
	lateLimit := flag.Duration("late-limit", 10*time.Millisecond, "slots later than this are recorded unsent (load.go: 10ms)")
	cold := flag.Bool("cold", false, "")
	group := flag.String("group", "mixed", "")
	kind := flag.String("type", "mixed", "")
	nameFlag := flag.String("name", "", "")
	unique := flag.Bool("unique", false, "")
	offset := flag.Int("offset", 0, "")
	timeout := flag.Duration("timeout", 2*time.Second, "")
	flag.Parse()
	if *rate < 1 || *rate > 20000 || *seconds < 1 || *seconds > 120 || *workers < 1 || *workers > 2048 {
		panic("bounds")
	}
	baseWall = time.Now()
	baseMono = clockMonotonic()
	names := []string{"www.baidu.com", "www.qq.com", "example.com", "www.cloudflare.com"}
	if *group == "cn" {
		names = names[:2]
	}
	if *group == "foreign" {
		names = names[2:]
	}
	n := *rate * *seconds
	samples := make([]Sample, n)
	jobs := make(chan job)
	conns := make([]net.Conn, *workers)
	predialed := make([]bool, *workers)
	if *predial {
		for w := range conns {
			c, e := net.DialTimeout(*network, *addr, time.Second)
			if e != nil {
				panic(e)
			}
			conns[w] = c
			predialed[w] = true
		}
	}
	var wg sync.WaitGroup
	start := time.Now().Add(200 * time.Millisecond)
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			c := conns[w]
			defer func() {
				if c != nil {
					c.Close()
				}
			}()
			for j := range jobs {
				now := time.Now()
				typ := 1
				if j.I%2 == 1 {
					typ = 28
				}
				if *kind == "A" {
					typ = 1
				} else if *kind == "AAAA" {
					typ = 28
				}
				name := names[(j.I/2)%len(names)]
				if *nameFlag != "" {
					name = *nameFlag
				}
				if *unique {
					name = fmt.Sprintf("q%d.cn.test", j.I+*offset)
				}
				s := Sample{I: j.I, ID: (j.I + 1) & 0xffff, Name: name, Type: typ, Worker: w, Slot: mono(j.At), Pickup: mono(now)}
				q := query(j.I+1, name, typ, *cold)
				var e error
				if c == nil {
					s.Connect0 = mono(time.Now())
					c, e = net.DialTimeout(*network, *addr, time.Second)
					s.Connect1 = mono(time.Now())
					s.ConnFirst = true
				}
				if e == nil {
					c.SetDeadline(time.Now().Add(*timeout))
					var r []byte
					s.Send = mono(time.Now())
					if *network == "tcp" {
						buf := append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
						_, e = c.Write(buf)
						if e == nil {
							h := make([]byte, 2)
							_, e = io.ReadFull(c, h)
							if e == nil {
								r = make([]byte, u16(h, 0))
								_, e = io.ReadFull(c, r)
							}
						}
					} else {
						_, e = c.Write(q)
						if e == nil {
							buf := make([]byte, 4096)
							for {
								var k int
								k, e = c.Read(buf)
								if e != nil {
									break
								}
								if k >= 2 && u16(buf, 0) == u16(q, 0) {
									r = buf[:k]
									break
								}
							}
						}
					}
					if e == nil {
						s.Recv = mono(time.Now())
						e = valid(q, r, typ)
					}
				}
				if e != nil {
					s.Error = e.Error()
					if c != nil {
						c.Close()
						c = nil
					}
				}
				samples[j.I] = s
			}
		}(w)
	}
	for i := 0; i < n; i++ {
		at := start.Add(time.Duration(i) * time.Second / time.Duration(*rate))
		time.Sleep(time.Until(at))
		now := time.Now()
		if now.Sub(at) > *lateLimit {
			samples[i] = Sample{I: i, Slot: mono(at), Pickup: mono(now), Unsent: "scheduler_late"}
			continue
		}
		select {
		case jobs <- job{i, at}:
		default:
			samples[i] = Sample{I: i, Slot: mono(at), Pickup: mono(now), Unsent: "inflight_limit"}
		}
	}
	close(jobs)
	wg.Wait()
	res := map[string]any{"schema": "diversion-diagload-v1", "addr": *addr, "net": *network, "rate": *rate,
		"seconds": *seconds, "workers": *workers, "predial": *predial, "late_limit_ms": float64(*lateLimit) / 1e6,
		"cold_cookie_bypass": *cold, "group": *group, "query_type": *kind, "unique": *unique, "offset": *offset,
		"name": *nameFlag, "clock": "CLOCK_MONOTONIC_ns", "start_ns": mono(start), "samples": samples}
	if e := json.NewEncoder(os.Stdout).Encode(res); e != nil {
		panic(e)
	}
	_ = predialed
}
