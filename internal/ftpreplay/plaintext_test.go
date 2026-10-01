package ftpreplay_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvmukilan/livewire/internal/ftpreplay"
	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/recording"
	"github.com/kvmukilan/livewire/internal/replay"
	"github.com/kvmukilan/livewire/internal/replaylab"
	"github.com/kvmukilan/livewire/internal/tlsreplay"
)

func TestCapturedFTPSDataIsDecryptedBeforeUploadOrComparison(t *testing.T) {
	cert, _, err := replaylab.LabCertificate()
	if err != nil {
		t.Fatal(err)
	}
	for _, active := range []bool{false, true} {
		for _, upload := range []bool{false, true} {
			name := "download"
			if upload {
				name = "upload"
			}
			if active {
				name += "-active"
			}
			t.Run(name, func(t *testing.T) {
				plain := []byte("independently encrypted binary transfer\x00\x01\xff")
				exchange := replaylab.Exchange{Server: plain}
				if upload {
					exchange.Client, exchange.Server = plain, nil
				}
				records, log, err := replaylab.EncryptConversation(cert, []replaylab.Exchange{exchange})
				if err != nil {
					t.Fatal(err)
				}
				if active {
					for i := range records {
						records[i].Client, records[i].Server = records[i].Server, records[i].Client
					}
				}
				path := filepath.Join(t.TempDir(), "encrypted.pcap")
				if err = replaylab.WriteTCPCapture(path, 45000, records); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				reader, err := pcapio.NewReader(file)
				if err != nil {
					t.Fatal(err)
				}
				var capture []*pcapio.Record
				for {
					r, e := reader.Read()
					if e == io.EOF {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
					capture = append(capture, r)
				}
				trace := replay.ExtractTrace(capture, replay.ExtractOptions{})
				if len(trace.Sessions) != 1 {
					t.Fatal("missing TLS data session")
				}
				control := *trace.Sessions[0]
				negotiation, reply, command := "EPSV", "229 passive", "RETR file"
				if active {
					control.Client, control.Server = control.Server, control.Client
					negotiation, reply = "PORT 192,0,2,1,1,1", "200 active"
				}
				if upload {
					command = "STOR file"
				}
				script := dataScript("PROT P", "200 protected", negotiation, reply, command, "150 transfer", "", "226 done")
				if _, err = ftpreplay.PrepareDataSessions(&control, script, trace.Sessions, nil); err == nil {
					t.Fatal("encrypted transfer accepted without keylog")
				}
				// Recording must retain the data channel's keys even when the
				// FTP server initiated TCP (active mode). Replay then uses only
				// these selected keys, as it would from the recorded PCAPNG.
				matched, count, err := recording.MatchSecrets(&pcapio.Capture{Records: capture}, log)
				if err != nil || count != 1 {
					t.Fatalf("recorded data channel secrets: count=%d err=%v", count, err)
				}
				keys, err := tlsreplay.ParseKeyLog(bytes.NewReader(matched))
				if err != nil {
					t.Fatal(err)
				}
				prepared, err := ftpreplay.PrepareDataSessions(&control, script, trace.Sessions, keys)
				if err != nil {
					t.Fatal(err)
				}
				client, server, err := replay.TCPPayloadStreams(prepared[0])
				if err != nil {
					t.Fatal(err)
				}
				got := server
				if upload != active {
					got = client
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("decrypted transfer=%x", got)
				}
				oldClient, oldServer, err := replay.TCPPayloadStreams(trace.Sessions[0])
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(oldClient, client) && bytes.Equal(oldServer, server) {
					t.Fatal("original encrypted evidence was mutated")
				}
				wrong, _ := tlsreplay.ParseKeyLog(bytes.NewReader(nil))
				if _, err = ftpreplay.PrepareDataSessions(&control, script, trace.Sessions, wrong); err == nil {
					t.Fatal("missing session secret accepted")
				}
			})
		}
	}
}

func dataScript(lines ...string) ftpreplay.Script {
	var script ftpreplay.Script
	for i, line := range lines {
		if line == "" {
			continue
		}
		dir := replay.ClientToServer
		if i%2 == 1 {
			dir = replay.ServerToClient
		}
		script.Turns = append(script.Turns, ftpreplay.Turn{Direction: dir, Message: replay.Message{Raw: []byte(line + "\r\n")}})
	}
	return script
}

func TestDataPreparationUsesAcceptedProtectionPerTransfer(t *testing.T) {
	// A legitimate binary file may begin with a TLS record header. Even a
	// rejected PROT P must leave this clear payload untouched.
	clear := &replay.Session{ID: "clear", Transport: replay.TransportTCP, Events: []replay.Event{{Direction: replay.ServerToClient, Payload: []byte{23, 3, 3, 0, 3, 1, 2, 3}}}}
	control := &replay.Session{ID: "control"}
	for _, script := range []ftpreplay.Script{
		dataScript("RETR file", "150 transfer", "", "226 done"),
		dataScript("PROT P", "534 denied", "RETR file", "150 transfer", "", "226 done"),
		dataScript("PROT P", "200 protected", "PROT C", "200 clear", "RETR file", "150 transfer", "", "226 done"),
	} {
		prepared, err := ftpreplay.PrepareDataSessions(control, script, []*replay.Session{clear}, nil)
		if err != nil || len(prepared) != 1 || prepared[0] != clear {
			t.Fatalf("clear binary payload was treated as TLS: %v", err)
		}
	}
	// These bytes could be a protected capture starting halfway through a TLS
	// record. Neither a missing header nor a rejected downgrade allows replay.
	partial := &replay.Session{ID: "partial", Transport: replay.TransportTCP, Events: []replay.Event{{Direction: replay.ServerToClient, Payload: []byte("opaque middle of encrypted record")}}}
	keys, _ := tlsreplay.ParseKeyLog(strings.NewReader(""))
	for _, script := range []ftpreplay.Script{
		dataScript("PROT P", "200 protected", "RETR file", "150 transfer", "", "226 done"),
		dataScript("PROT P", "200 protected", "PROT C", "534 denied", "RETR file", "150 transfer", "", "226 done"),
	} {
		if _, err := ftpreplay.PrepareDataSessions(control, script, []*replay.Session{partial}, keys); err == nil {
			t.Fatal("protected mid-record capture was accepted as plaintext")
		}
	}
	// Each transfer keeps its own setting, even within one control session.
	script := dataScript("PROT C", "200 clear", "RETR first", "150 first", "", "226 done", "PROT P", "200 protected", "RETR second", "150 second", "", "226 done")
	if _, err := ftpreplay.PrepareDataSessions(control, script, []*replay.Session{clear, partial}, keys); err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("per-transfer protection lost: %v", err)
	}
	unsupported := dataScript("PROT S", "200 accepted", "RETR file", "150 transfer", "", "226 done")
	if _, err := ftpreplay.PrepareDataSessions(control, unsupported, []*replay.Session{clear}, nil); err == nil {
		t.Fatal("unsupported accepted protection mode treated as clear")
	}
}
