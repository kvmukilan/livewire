package adapters

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/kvmukilan/livewire/internal/replay"
)

func TestHTTPEmptyChunkedBodyPreservesNextRequest(t *testing.T) {
	a := HTTP{}
	messages, err := a.Decode(replay.ClientToServer, []byte("POST /first HTTP/1.1\r\nHost: device\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nold\r\n0\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := a.Prepare(replay.ClientToServer, messages[0], replay.NewRuntimeState(map[string]string{"http.body": ""}))
	if err != nil {
		t.Fatal(err)
	}
	next := []byte("GET /next HTTP/1.1\r\nHost: device\r\n\r\n")
	decoded, err := a.Decode(replay.ClientToServer, append(prepared, next...))
	if err != nil || len(decoded) != 2 || !bytes.Equal(decoded[1].Raw, next) {
		t.Fatalf("empty chunk corrupted next request: messages=%+v err=%v", decoded, err)
	}
	if body, err := decodedHTTPBody(decoded[0]); err != nil || len(body) != 0 {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestHTTPOversizedContentLengthCannotOverflow(t *testing.T) {
	length := strconv.FormatUint(uint64(^uint(0)>>1), 10)
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: " + length + "\r\n\r\n")
	if _, err := (HTTP{}).Decode(replay.ServerToClient, raw); err == nil {
		t.Fatal("oversized incomplete response decoded successfully")
	}
	if _, _, err := (HTTP{}).DecodeAvailable(replay.ServerToClient, raw, nil, true); err == nil {
		t.Fatal("oversized incomplete response decoded at EOF")
	}
}
