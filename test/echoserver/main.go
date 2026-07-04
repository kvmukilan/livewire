// Command echoserver is a tiny TCP echo server used as the stand-in "device" for
// livewire's live-replay tests: it completes a real TCP handshake and echoes
// back whatever it receives (prefixed), so the replay engine has a live peer to
// learn an ISN from and exchange data with. Dependency-free; runs on any OS.
//
// Usage: go run ./test/echoserver -addr 127.0.0.1:9502
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9502", "host:port to listen on")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	fmt.Printf("echo server listening on %s\n", *addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			fmt.Printf("recv %d bytes from %s: %q\n", n, c.RemoteAddr(), buf[:n])
			c.Write(append([]byte("ECHO:"), buf[:n]...))
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("read: %v", err)
			}
			return
		}
	}
}
