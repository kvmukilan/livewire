package replay

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type batchFrameAdapter struct{ fourByteAdapter }

func (batchFrameAdapter) DecodeAvailable(_ Direction, data []byte, _ []Message, eof bool) ([]Message, int, error) {
	var out []Message
	n := len(data) / 4 * 4
	for i := 0; i < n; i += 4 {
		out = append(out, Message{Raw: append([]byte(nil), data[i:i+4]...)})
	}
	if eof && n == 0 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return out, n, nil
}

func TestMessageReaderKeepsBatchedFramesForNextExchange(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		_, _ = server.Write([]byte("one!two!"))
	}()
	var reader MessageReader
	state := NewRuntimeState(nil)
	for _, body := range []string{"one!", "two!"} {
		actual, err := reader.ReadExchange(context.Background(), client, batchFrameAdapter{}, []Message{{Raw: []byte(body)}}, nil, state, time.Second)
		if err != nil || len(actual) != 1 || string(actual[0].Raw) != body {
			t.Fatalf("response %q lost: actual=%+v err=%v", body, actual, err)
		}
	}
}

type failingNormalizerAdapter struct {
	fourByteAdapter
	err error
}

func (a failingNormalizerAdapter) NormalizeExpected(Direction, Message, *RuntimeState) (Message, error) {
	return Message{}, a.err
}

func TestMessageReaderPropagatesNormalizationFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		_, _ = server.Write([]byte("pong"))
	}()
	wantErr := errors.New("missing runtime variable")
	var reader MessageReader
	_, err := reader.ReadExchange(context.Background(), client, failingNormalizerAdapter{err: wantErr}, []Message{{Raw: []byte("pong")}}, nil, NewRuntimeState(nil), time.Second)
	if !errors.Is(err, wantErr) {
		t.Fatalf("normalization failure lost: %v", err)
	}
}

func TestMessageReaderCancellationBeforeBufferedResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := MessageReader{decoded: []Message{{Raw: []byte("pong")}}}
	_, err := reader.Read(ctx, nil, batchFrameAdapter{}, ServerToClient, []Message{{Raw: []byte("pong")}}, nil, time.Second)
	if !errors.Is(err, context.Canceled) || len(reader.decoded) != 1 {
		t.Fatalf("cancelled read consumed a queued response: err=%v remaining=%d", err, len(reader.decoded))
	}
}

type failingMaintenanceAdapter struct{ fourByteAdapter }

func (failingMaintenanceAdapter) Maintenance(time.Time, *RuntimeState) ([]Message, time.Time, error) {
	return nil, time.Time{}, context.DeadlineExceeded
}

func TestExpectedResponseFailureMarkerExcludesMaintenanceAndCancellation(t *testing.T) {
	for _, kind := range []string{"response timeout", "maintenance timeout", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var adapter Adapter = fourByteAdapter{}
			if kind == "cancelled" {
				cancel()
			}
			if kind == "maintenance timeout" {
				adapter = failingMaintenanceAdapter{}
			}
			var reader MessageReader
			_, err := reader.ReadExchange(ctx, client, adapter, []Message{{Raw: []byte("pong")}}, nil, NewRuntimeState(nil), 15*time.Millisecond)
			var observed *ResponseReadError
			if marked := errors.As(err, &observed); marked != (kind == "response timeout") {
				t.Fatalf("wrong response failure evidence: marked=%v err=%v", marked, err)
			}
		})
	}
}

func TestClosedProtocolPacingDoesNotRequireAnotherResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	_ = server.Close()
	state := NewRuntimeState(nil)
	state.Phase = SessionClosed
	var reader MessageReader
	start := time.Now()
	if err := reader.WaitUntil(context.Background(), client, batchFrameAdapter{}, nil, nil, state, start.Add(30*time.Millisecond), time.Second); err != nil {
		t.Fatalf("orderly protocol shutdown became a read failure: %v", err)
	}
	if time.Since(start) < 25*time.Millisecond {
		t.Fatal("final captured pacing delay was skipped")
	}
	// A protocol phase alone cannot waive an outstanding captured response.
	if err := reader.WaitUntil(context.Background(), client, batchFrameAdapter{}, []Message{{Raw: []byte("pong")}}, nil, state, time.Now().Add(time.Second), time.Second); err == nil {
		t.Fatal("closed protocol hid a missing captured response")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := reader.WaitUntil(ctx, client, batchFrameAdapter{}, nil, nil, state, time.Now().Add(time.Second), time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed protocol lost cancellation: %v", err)
	}
}
