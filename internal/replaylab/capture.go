package replaylab

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/kvmukilan/livewire/internal/pcapio"
	"github.com/kvmukilan/livewire/internal/wire"
)

// WriteTCPCapture writes a complete synthetic connection containing the peer's
// independently specified bytes. Its addresses identify software fixtures.
func WriteTCPCapture(path string, serverPort uint16, exchanges []Exchange) (retErr error) {
	return WriteTCPConversations(path, []TCPConversation{{ServerPort: serverPort, Exchanges: exchanges}})
}

type TCPConversation struct {
	ServerPort uint16
	ClientPort uint16
	Start      time.Duration
	Exchanges  []Exchange
}

func WriteTCPConversations(path string, conversations []TCPConversation) (retErr error) {
	var records []*pcapio.Record
	for _, conversation := range conversations {
		var data bytes.Buffer
		if err := writeTCPCapture(&data, conversation.ServerPort, conversation.Exchanges); err != nil {
			return err
		}
		reader, err := pcapio.NewReader(bytes.NewReader(data.Bytes()))
		if err != nil {
			return err
		}
		for {
			record, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			record.Time = record.Time.Add(conversation.Start)
			if conversation.ClientPort != 0 {
				p, err := wire.Parse(record.Data, record.LinkType)
				if err != nil {
					return err
				}
				if p.SrcIP() == netip.MustParseAddr("192.0.2.10") {
					p.SetSrcPort(conversation.ClientPort)
				} else {
					p.SetDstPort(conversation.ClientPort)
				}
				p.RecalcChecksums()
			}
			records = append(records, record)
		}
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Time.Before(records[j].Time) })
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); retErr == nil {
			retErr = err
		}
	}()
	w, err := pcapio.NewWriter(file, wire.LinkEthernet, true)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := w.Write(record); err != nil {
			return err
		}
	}
	return w.Flush()
}

func writeTCPCapture(output io.Writer, serverPort uint16, exchanges []Exchange) error {
	w, err := pcapio.NewWriter(output, wire.LinkEthernet, true)
	if err != nil {
		return err
	}
	clientSeq, serverSeq := uint32(10000), uint32(50000)
	base := time.Unix(1700000000, 0)
	at := time.Duration(0)
	write := func(client bool, flags uint8, payload []byte) error {
		if len(payload) > 60000 {
			return fmt.Errorf("lab TCP segment exceeds fixture limit")
		}
		data := make([]byte, 54+len(payload))
		copy(data[:12], []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1})
		binary.BigEndian.PutUint16(data[12:14], 0x0800)
		ip := data[14:34]
		ip[0], ip[8], ip[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(ip[2:4], uint16(40+len(payload)))
		src, dst := []byte{192, 0, 2, 10}, []byte{198, 51, 100, 20}
		sport, dport := uint16(41000), serverPort
		seq, ack := clientSeq, serverSeq
		if !client {
			src, dst = dst, src
			sport, dport = dport, sport
			seq, ack = ack, seq
		}
		copy(ip[12:16], src)
		copy(ip[16:20], dst)
		tcp := data[34:]
		binary.BigEndian.PutUint16(tcp[:2], sport)
		binary.BigEndian.PutUint16(tcp[2:4], dport)
		binary.BigEndian.PutUint32(tcp[4:8], seq)
		if flags&wire.FlagACK != 0 {
			binary.BigEndian.PutUint32(tcp[8:12], ack)
		}
		tcp[12], tcp[13] = 5<<4, flags
		binary.BigEndian.PutUint16(tcp[14:16], 65535)
		copy(tcp[20:], payload)
		p, err := wire.Parse(data, wire.LinkEthernet)
		if err != nil {
			return err
		}
		p.RecalcChecksums()
		if err := w.Write(&pcapio.Record{Time: base.Add(at), Data: data, CapLen: len(data), OrigLen: len(data), LinkType: wire.LinkEthernet}); err != nil {
			return err
		}
		n := uint32(len(payload))
		if flags&(wire.FlagSYN|wire.FlagFIN) != 0 {
			n++
		}
		if client {
			clientSeq += n
		} else {
			serverSeq += n
		}
		at += time.Millisecond
		return nil
	}
	if err = write(true, wire.FlagSYN, nil); err != nil {
		return err
	}
	if err = write(false, wire.FlagSYN|wire.FlagACK, nil); err != nil {
		return err
	}
	if err = write(true, wire.FlagACK, nil); err != nil {
		return err
	}
	for _, exchange := range exchanges {
		if exchange.At > at {
			at = exchange.At
		}
		if len(exchange.Client) > 0 {
			if err = write(true, wire.FlagACK|wire.FlagPSH, exchange.Client); err != nil {
				return err
			}
		}
		if len(exchange.Server) > 0 {
			if err = write(false, wire.FlagACK|wire.FlagPSH, exchange.Server); err != nil {
				return err
			}
		}
	}
	if err = write(true, wire.FlagFIN|wire.FlagACK, nil); err != nil {
		return err
	}
	if err = write(false, wire.FlagFIN|wire.FlagACK, nil); err != nil {
		return err
	}
	if err = write(true, wire.FlagACK, nil); err != nil {
		return err
	}
	return w.Flush()
}
