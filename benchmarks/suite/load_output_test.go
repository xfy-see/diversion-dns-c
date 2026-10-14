package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func outputFixture(samples []Sample) map[string]any {
	first := time.Date(2026, 10, 14, 1, 2, 3, 456789123, time.FixedZone("fixture", 5*3600+30*60))
	return map[string]any{
		"query_type": "mixed", "addr": "192.0.2.1:15491", "net": "udp",
		"rate": 2000, "seconds": 45, "workers": 32, "cold_cookie_bypass": false,
		"group": "mixed", "offered": len(samples), "sent": len(samples),
		"success": len(samples), "unsent": 0, "success_qps": 1999.25,
		"success_of_offered_percent": 99.999, "p50_ms": math.Copysign(0, -1),
		"p95_ms": 1.25, "p99_ms": 2.5, "max_ms": 5000.125,
		"send_late_p99_ms": 0.001, "first_send": first,
		"last_send": first.Add(45*time.Second + 123*time.Nanosecond),
		"errors": map[string]int{}, "samples": samples,
	}
}

func outputSamples(count int) []Sample {
	samples := make([]Sample, count)
	for i := range samples {
		typ := 1
		if i%2 != 0 {
			typ = 28
		}
		samples[i] = Sample{I: i, Name: fmt.Sprintf("q%d.cn.test", i), Type: typ,
			MS: float64(i%1000) / 1000, Late: float64(i%10) / 1000}
	}
	return samples
}

func assertOutputOracle(t *testing.T, result map[string]any) []byte {
	t.Helper()
	var want, got bytes.Buffer
	if err := json.NewEncoder(&want).Encode(result); err != nil {
		t.Fatalf("legacy oracle: %v", err)
	}
	if err := writeResult(&got, result); err != nil {
		t.Fatalf("stream output: %v", err)
	}
	if !bytes.Equal(want.Bytes(), got.Bytes()) {
		t.Fatalf("JSON differs from legacy oracle: want %d bytes, got %d", want.Len(), got.Len())
	}
	decoder := json.NewDecoder(bytes.NewReader(got.Bytes()))
	var document json.RawMessage
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("first JSON document: %v", err)
	}
	if err := decoder.Decode(&document); err != io.EOF {
		t.Fatalf("expected exactly one JSON document, got %v", err)
	}
	if got.Len() == 0 || got.Bytes()[got.Len()-1] != '\n' {
		t.Fatal("missing legacy trailing newline")
	}
	return got.Bytes()
}

func TestResultOutputOracle(t *testing.T) {
	for _, count := range []int{0, 1, 90000} {
		t.Run(fmt.Sprintf("samples-%d", count), func(t *testing.T) {
			samples := outputSamples(count)
			data := assertOutputOracle(t, outputFixture(samples))
			var decoded struct {
				Samples []Sample `json:"samples"`
			}
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if len(decoded.Samples) != count {
				t.Fatalf("sample count: got %d, want %d", len(decoded.Samples), count)
			}
			for i, sample := range decoded.Samples {
				if sample != samples[i] {
					t.Fatalf("sample order/content differs at %d", i)
				}
			}
		})
	}
}

func TestResultOutputNilAndEmpty(t *testing.T) {
	for name, result := range map[string]map[string]any{
		"nil-map": nil, "empty-map": {},
		"nil-samples": outputFixture(nil), "empty-samples": outputFixture([]Sample{}),
		"null-interface": {"samples": nil},
	} {
		t.Run(name, func(t *testing.T) { assertOutputOracle(t, result) })
	}
}

func TestResultOutputErrorsEscapesFloatsAndTimes(t *testing.T) {
	samples := []Sample{
		{I: 0, Name: "quote\" slash\\ tab\t newline\n <>& \u2028 \u2029 中文 \xff", Type: 1, MS: math.SmallestNonzeroFloat64, Late: math.Copysign(0, -1)},
		{I: 1, Name: "q1.cn.test", Type: 28, MS: math.MaxFloat64, Late: 11.125, Error: "read: \"timeout\" <&>"},
		{I: 2, Error: "scheduler_late_over_10ms"},
		{I: 3, Error: "inflight_limit"},
	}
	result := outputFixture(samples)
	result["errors"] = map[string]int{"scheduler_late_over_10ms": 1, "inflight_limit": 1, "read: \"timeout\" <&>": 1}
	result["sent"], result["success"], result["unsent"] = 2, 1, 2
	result["a\"<&>\u2028"] = "metadata\n<&>\u2029"
	result["first_send"] = time.Time{}
	assertOutputOracle(t, result)
}

type outputCountingWriter struct {
	destination io.Writer
	bytes       int64
	writes      int
	maxWrite    int
}

func (w *outputCountingWriter) Write(data []byte) (int, error) {
	w.writes++
	if len(data) > w.maxWrite {
		w.maxWrite = len(data)
	}
	n, err := w.destination.Write(data)
	w.bytes += int64(n)
	return n, err
}

func TestResultOutputWriterChunkBound(t *testing.T) {
	result := outputFixture([]Sample{{I: 0, Name: strings.Repeat("<&>", resultOutputBufferSize)}})
	result["large_metadata"] = strings.Repeat("x", 3*resultOutputBufferSize)
	var output bytes.Buffer
	writer := &outputCountingWriter{destination: &output}
	if err := writeResult(writer, result); err != nil {
		t.Fatal(err)
	}
	if writer.maxWrite > resultOutputBufferSize || writer.writes < 2 {
		t.Fatalf("unbounded/chunkless writes: max=%d writes=%d", writer.maxWrite, writer.writes)
	}
	if want := assertOutputOracle(t, result); !bytes.Equal(output.Bytes(), want) {
		t.Fatal("chunked output differs")
	}
}

var errOutputWriter = errors.New("intentional output writer error")

type outputFailWriter struct{ remaining int }

func (w *outputFailWriter) Write(data []byte) (int, error) {
	if len(data) <= w.remaining {
		w.remaining -= len(data)
		return len(data), nil
	}
	n := w.remaining
	w.remaining = 0
	return n, errOutputWriter
}

type outputShortWriter struct{}

func (outputShortWriter) Write(data []byte) (int, error) {
	return len(data) / 2, nil
}

func TestResultOutputWriterErrors(t *testing.T) {
	for name, result := range map[string]map[string]any{
		"flush": outputFixture(outputSamples(1)),
		"buffered-write": outputFixture(outputSamples(2000)),
		"nil-flush": nil,
	} {
		t.Run(name, func(t *testing.T) {
			err := writeResult(&outputFailWriter{}, result)
			if !errors.Is(err, errOutputWriter) {
				t.Fatalf("writer error not propagated: %v", err)
			}
			err = writeResult(outputShortWriter{}, result)
			if !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("short writer not rejected: %v", err)
			}
		})
	}
	err := writeResult(&outputFailWriter{remaining: resultOutputBufferSize + 17}, outputFixture(outputSamples(2000)))
	if !errors.Is(err, errOutputWriter) {
		t.Fatalf("error after partial output not propagated: %v", err)
	}
}

func TestResultOutputMarshalErrors(t *testing.T) {
	for name, result := range map[string]map[string]any{
		"sample-NaN": outputFixture([]Sample{{MS: math.NaN()}}),
		"sample-infinity": outputFixture([]Sample{{Late: math.Inf(1)}}),
		"metadata-channel": {"unsupported": make(chan int)},
		"metadata-time": {"first_send": time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := json.NewEncoder(io.Discard).Encode(result); err == nil {
				t.Fatal("fixture unexpectedly accepted by oracle")
			}
			if err := writeResult(io.Discard, result); err == nil {
				t.Fatal("marshal error ignored")
			}
		})
	}
}

// This explicit opt-in test generates no DNS/network traffic. The separately
// compiled Linux test executable lets a device runner inspect its own peak RSS
// before any fixed-arrival load is attempted. The ordinary test suite skips it.
// It probes final output with retained samples/statistics, not the DNS sending
// phase or its peak memory. Unique names are a conservative fixture choice.
func TestResultOutputMemoryProbe(t *testing.T) {
	if os.Getenv("DIVERSION_LOAD_OUTPUT_MEMORY_PROBE") != "1" {
		t.Skip("set DIVERSION_LOAD_OUTPUT_MEMORY_PROBE=1 for the isolated 90k-sample output probe")
	}
	if runtime.GOOS != "linux" {
		t.Skip("MaxRSS KiB contract is Linux-only")
	}
	const count = 90000
	samples := outputSamples(count)
	lat, late := []float64{}, []float64{}
	for i, sample := range samples {
		if sample.I != i {
			t.Fatalf("input order differs at %d", i)
		}
		lat = append(lat, sample.MS)
		late = append(late, sample.Late)
	}
	result := outputFixture(samples)
	result["p50_ms"], result["p95_ms"], result["p99_ms"] = pct(lat, .5), pct(lat, .95), pct(lat, .99)
	result["max_ms"], result["send_late_p99_ms"] = pct(lat, 1), pct(late, .99)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	writer := &outputCountingWriter{destination: io.Discard}
	if err := writeResult(writer, result); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(samples)
	runtime.KeepAlive(lat)
	runtime.KeepAlive(late)
	runtime.KeepAlive(result)
	if writer.bytes == 0 || writer.maxWrite > resultOutputBufferSize {
		t.Fatalf("output contract: bytes=%d maxWrite=%d", writer.bytes, writer.maxWrite)
	}
	report := map[string]any{
		"schema": "diversion-load-output-memory-v1", "samples": count,
		"bytes": writer.bytes, "writes": writer.writes, "max_write_bytes": writer.maxWrite,
		"buffer_bytes": resultOutputBufferSize, "first_i": 0, "last_i": count - 1,
		"input_order_verified": true, "output_order_contract": "slice order, checked against legacy encoder by unit tests",
		"network_requests": 0, "maxrss_kib": usage.Maxrss, "goarch": runtime.GOARCH,
		"scope": "post-load serialization probe; not DNS sending-phase peak memory",
		"heap_alloc_before": before.HeapAlloc, "heap_alloc_after": after.HeapAlloc,
		"heap_inuse_before": before.HeapInuse, "heap_inuse_after": after.HeapInuse,
		"heap_sys_before": before.HeapSys, "heap_sys_after": after.HeapSys,
		"total_alloc_before": before.TotalAlloc, "total_alloc_after": after.TotalAlloc,
		"num_gc_before": before.NumGC, "num_gc_after": after.NumGC,
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("RESULT_OUTPUT_MEMORY_PROBE %s", encoded)
}
