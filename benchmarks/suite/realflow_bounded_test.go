//go:build linux
package main
import("bytes";"os";"strings";"testing";"time")
func TestBoundedExitAndLiteralArguments(t *testing.T){var out,err bytes.Buffer;code:=bounded(3,[]string{"sh","-c","printf '%s' \"$1\"; exit 7","fixture","a;$(false) b"},&out,&err,make(chan os.Signal));if code!=7||out.String()!="a;$(false) b"{t.Fatalf("code=%d out=%q err=%q",code,out.String(),err.String())}}
func TestBoundedKillsNestedSleeper(t *testing.T){var out,err bytes.Buffer;start:=time.Now();code:=bounded(1,[]string{"sh","-c","sleep 20 & wait"},&out,&err,make(chan os.Signal));if code!=124||time.Since(start)>4*time.Second||!strings.Contains(err.String(),"timed out"){t.Fatalf("code=%d elapsed=%s stderr=%s",code,time.Since(start),err.String())}}
func TestBoundedRejectsInvalidAndMissingCommand(t *testing.T){for _,seconds:=range []int{0,61}{if c:=bounded(seconds,[]string{"true"},&bytes.Buffer{},&bytes.Buffer{},nil);c!=2{t.Fatal(c)}};if c:=bounded(1,nil,&bytes.Buffer{},&bytes.Buffer{},nil);c!=2{t.Fatal(c)};if c:=bounded(1,[]string{"/no-such-owned-ab24-command"},&bytes.Buffer{},&bytes.Buffer{},nil);c!=125{t.Fatal(c)}}
