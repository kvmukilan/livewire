package tlsreplay

import "testing"

func FuzzTLSRecordAndHandshakeParsing(f *testing.F) {
	f.Add([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{23, 3, 3, 0, 1, 0})
	f.Add(helloStream(helloBody(helloExtension(43, []byte{4, 3, 4, 3, 3}))))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = parseRecords(data)
		_, _ = firstHandshake(data, 1)
		_, _, _ = serverHelloParams(data)
		_, _ = ParseClientHello(data)
	})
}
