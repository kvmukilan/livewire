//go:build ignore

// Run each case in a separate process: go run scripts/qualifybench.go -mib 10
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/replayintent"
	"github.com/kvmukilan/livewire/internal/wire"
)

func main() {
	if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}

func run() error {
	mib := flag.Int("mib", 10, "decoded packet MiB; 10, 100, 512, or 513")
	records := flag.Int("records", 0, "use 1000000 or 1000001 minimum-size records instead")
	flag.Parse()
	if *records != 0 && *records != 1000000 && *records != 1000001 { return fmt.Errorf("records must be 1000000 or 1000001") }
	if *mib != 10 && *mib != 100 && *mib != 512 && *mib != 513 { return fmt.Errorf("mib must be 10, 100, 512, or 513") }
	frameSize, count := 1024, (*mib<<20)/1024
	if *records != 0 { frameSize, count = 60, *records }
	f, err := os.CreateTemp("", "livewire-bench-*.pcap")
	if err != nil { return err }
	defer os.Remove(f.Name())
	w := bufio.NewWriterSize(f, 1<<20)
	header := make([]byte,24)
	binary.LittleEndian.PutUint32(header,0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:],2); binary.LittleEndian.PutUint16(header[6:],4)
	binary.LittleEndian.PutUint32(header[16:],65535); binary.LittleEndian.PutUint32(header[20:],1)
	if _,err = w.Write(header); err != nil { f.Close(); return err }
	frame := make([]byte,frameSize)
	binary.BigEndian.PutUint16(frame[12:],0x0800)
	frame[14],frame[22],frame[23] = 0x45,64,17
	binary.BigEndian.PutUint16(frame[16:],uint16(frameSize-14))
	copy(frame[26:30],[]byte{192,0,2,1}); copy(frame[30:34],[]byte{192,0,2,2})
	binary.BigEndian.PutUint16(frame[34:],40000); binary.BigEndian.PutUint16(frame[36:],40001)
	binary.BigEndian.PutUint16(frame[38:],uint16(frameSize-34))
	p,err := wire.Parse(frame,wire.LinkEthernet); if err != nil { f.Close(); return err }; p.RecalcChecksums()
	rh := make([]byte,16)
	binary.LittleEndian.PutUint32(rh[8:],uint32(frameSize)); binary.LittleEndian.PutUint32(rh[12:],uint32(frameSize))
	for i:=0;i<count;i++ {
		binary.LittleEndian.PutUint32(rh,uint32(i/1000)); binary.LittleEndian.PutUint32(rh[4:],uint32((i%1000)*1000))
		if _,err=w.Write(rh);err!=nil { f.Close();return err }; if _,err=w.Write(frame);err!=nil { f.Close();return err }
	}
	err=errors.Join(w.Flush(),f.Close()); if err!=nil{return err}
	runtime.GC()
	var peak uint64
	var wg sync.WaitGroup
	done:=make(chan struct{}); wg.Add(1)
	go func(){ defer wg.Done(); tick:=time.NewTicker(10*time.Millisecond); defer tick.Stop(); for { var m runtime.MemStats;runtime.ReadMemStats(&m);if m.HeapAlloc>peak{peak=m.HeapAlloc};select{case <-done:return;case <-tick.C:} } }()
	start:=time.Now()
	capture,loadErr:=pcapio.LoadFile(f.Name(),pcapio.DefaultLimits())
	loadTime:=time.Since(start)
	var planErr error; var planTime time.Duration
	if loadErr==nil { start=time.Now(); _,planErr=replayintent.Inspect(capture.Records,replayintent.Options{Mode:"transport"},nil);planTime=time.Since(start) }
	close(done);wg.Wait()
	var mem runtime.MemStats;runtime.ReadMemStats(&mem)
	wantLimit:=int64(count)*int64(frameSize)>512<<20 || count>1000000
	passed:=planErr==nil && ((wantLimit && errors.Is(loadErr,pcapio.ErrLimit)) || (!wantLimit && loadErr==nil))
	reason:="";if err:=errors.Join(loadErr,planErr);err!=nil{reason=err.Error()}
	result:=map[string]any{"platform":runtime.GOOS+"/"+runtime.GOARCH,"go":runtime.Version(),"decodedBytes":int64(count)*int64(frameSize),"records":count,"loadSeconds":loadTime.Seconds(),"planSeconds":planTime.Seconds(),"sampledPeakHeapBytes":peak,"runtimeReservedBytes":mem.Sys,"memoryMethod":"Go heap sampled every 10ms; runtime reservation is not process RSS","expectedLimit":wantLimit,"passed":passed,"error":reason}
	if err:=json.NewEncoder(os.Stdout).Encode(result);err!=nil{return err}
	if !passed{return fmt.Errorf("qualification benchmark failed")};return nil
}
