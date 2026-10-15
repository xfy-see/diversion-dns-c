//go:build linux

// Run one owned supervision command with a bounded process group. Cloud-build only.
package main

import (
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "os/exec"
 "os/signal"
 "sync"
 "syscall"
 "time"
)

type boundedWriter struct { mu *sync.Mutex; writer io.Writer }
func (w boundedWriter) Write(p []byte) (int,error) { w.mu.Lock();defer w.mu.Unlock();return w.writer.Write(p) }

func bounded(seconds int, argv []string, stdout, stderr io.Writer, stop <-chan os.Signal) int {
 // os/exec copies both child streams concurrently with our timeout messages.
 // One mutex also handles callers passing the same writer for both streams.
 var outputMu sync.Mutex
 stdout=boundedWriter{&outputMu,stdout};stderr=boundedWriter{&outputMu,stderr}
 if seconds<1 || seconds>60 || len(argv)==0 {fmt.Fprintln(stderr,"bounded: invalid seconds or empty command");return 2}
 cmd:=exec.Command(argv[0],argv[1:]...)
 cmd.Stdin=nil;cmd.Stdout=stdout;cmd.Stderr=stderr
 cmd.SysProcAttr=&syscall.SysProcAttr{Setpgid:true}
 if err:=cmd.Start();err!=nil {fmt.Fprintln(stderr,"bounded start:",err);return 125}
 done:=make(chan error,1)
 go func(){done<-cmd.Wait()}()
 timer:=time.NewTimer(time.Duration(seconds)*time.Second);defer timer.Stop()
 code:=124
 select {
 case err:=<-done:
  if err==nil{return 0};var exit *exec.ExitError
  if errors.As(err,&exit) {if n:=exit.ExitCode();n>=0{return n};return 125}
  fmt.Fprintln(stderr,"bounded wait:",err);return 125
 case <-timer.C:fmt.Fprintln(stderr,"bounded: command timed out")
 case <-stop:code=143;fmt.Fprintln(stderr,"bounded: interrupted")
 }
 // cmd started a fresh process group: this never signals the caller's group.
 if err:=syscall.Kill(-cmd.Process.Pid,syscall.SIGKILL);err!=nil && err!=syscall.ESRCH {fmt.Fprintln(stderr,"bounded kill:",err)}
 select {case <-done:case <-time.After(2*time.Second):fmt.Fprintln(stderr,"bounded: child did not reap after SIGKILL")}
 return code
}

func main(){seconds:=flag.Int("seconds",10,"deadline, 1..60 seconds");flag.Parse();stop:=make(chan os.Signal,1);signal.Notify(stop,os.Interrupt,syscall.SIGTERM);defer signal.Stop(stop);os.Exit(bounded(*seconds,flag.Args(),os.Stdout,os.Stderr,stop))}
