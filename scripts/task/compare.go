package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kvmukilan/livewire/internal/qualification"
)

// referenceReleases are the published builds whose behavior the current tree
// is compared against. Each needs a committed dist/v<version>/SHA256SUMS.
var referenceReleases = []string{"0.7.0", "0.8.0"}

type command struct {
	name string
	args []string
}

// compareReleases reproduces the release audit's published-behavior check.
// The same synthetic gzip HTTP captures and loopback server are driven
// through each published executable and the current build, and the outcomes
// that distinguished 0.7 from the 0.8 regression are asserted.
//
// Reference executables are downloaded from the GitHub release with gh and
// verified against the committed checksum manifest before they run; nothing
// unverified is executed. -reference-dir points at local copies instead.
func compareReleases(ctx context.Context, args []string) error {
	var output, exe, referenceDir string
	err := parseOptions("compare-releases", args, func(fs *flag.FlagSet) {
		fs.StringVar(&output, "output", "", "new evidence directory (required)")
		fs.StringVar(&exe, "exe", "", "current executable to compare (default: build ./cmd/livewire)")
		fs.StringVar(&referenceDir, "reference-dir", "", "directory holding the published reference executables (default: download with gh)")
	})
	if err != nil {
		return err
	}
	if output == "" {
		return errors.New("compare-releases requires -output <new directory>")
	}
	if output, err = filepath.Abs(output); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	if err := os.Mkdir(output, 0o755); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "livewire-compare-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	executables := map[string]string{}
	for _, version := range referenceReleases {
		path, err := referenceExecutable(ctx, version, referenceDir, work)
		if err != nil {
			return err
		}
		executables[version] = path
	}
	if exe == "" {
		exe = filepath.Join(work, "livewire"+exeSuffix())
		if err := sh(ctx, "go", "build", "-buildvcs=false", "-o", exe, "./cmd/livewire"); err != nil {
			return err
		}
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return err
	}
	executables["current"] = exe

	body := gzipBody()
	results := map[string]map[string]any{}
	labels := append(append([]string{}, referenceReleases...), "current")
	for _, label := range labels {
		outcomes, err := compareOne(ctx, label, executables[label], output, body)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		results[label] = outcomes
	}
	encoded, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "comparison.json"), append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Println(string(encoded))

	exit := func(label, name string) int {
		outcome, _ := results[label][name].(map[string]any)
		code, _ := outcome["exitCode"].(int)
		return code
	}
	requests := func(label string) int64 {
		n, _ := results[label]["localhostRequests"].(int64)
		return n
	}
	var failures []string
	expect := func(ok bool, what string) {
		if !ok {
			failures = append(failures, what)
		}
	}
	expect(exit("0.7.0", "gzip-replay") == 0, "0.7.0 replays valid gzip HTTP")
	expect(requests("0.7.0") == 1, "0.7.0 reaches the loopback server once")
	expect(exit("0.8.0", "gzip-replay") != 0, "0.8.0 still shows the gzip regression")
	expect(requests("0.8.0") == 0, "0.8.0 sends nothing for the regressed capture")
	expect(exit("current", "gzip-replay") == 0, "current build replays valid gzip HTTP")
	expect(exit("current", "selected-preview") == 0, "current build previews a selected session")
	expect(exit("current", "selected-replay") == 0, "current build replays a selected session beside background ARP")
	expect(requests("current") == 2, "current build reaches the loopback server exactly twice")
	if len(failures) > 0 {
		return errors.New("published replay regression: " + strings.Join(failures, "; "))
	}
	return nil
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// referenceExecutable obtains one published executable and verifies it against
// the committed release manifest before returning its path.
func referenceExecutable(ctx context.Context, version, referenceDir, work string) (string, error) {
	asset := fmt.Sprintf("livewire-%s-%s-%s%s", version, runtime.GOOS, runtime.GOARCH, exeSuffix())
	manifest, err := os.ReadFile(filepath.Join("dist", "v"+version, "SHA256SUMS"))
	if err != nil {
		return "", fmt.Errorf("release manifest for %s: %w", version, err)
	}
	want, ok := qualification.ManifestSHA256(manifest, asset)
	if !ok {
		return "", fmt.Errorf("dist/v%s/SHA256SUMS does not list %s", version, asset)
	}
	// A local reference directory may be flat or laid out like dist/v<version>/.
	path := filepath.Join(referenceDir, "v"+version, asset)
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(referenceDir, asset)
	}
	if referenceDir == "" {
		dir := filepath.Join(work, "v"+version)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		if err := sh(ctx, "gh", "release", "download", "v"+version, "--repo", "kvmukilan/livewire", "--pattern", asset, "--dir", dir); err != nil {
			return "", fmt.Errorf("download %s (pass -reference-dir to use local copies): %w", asset, err)
		}
		path = filepath.Join(dir, asset)
	}
	got, err := qualification.FileSHA256(path)
	if err != nil {
		return "", err
	}
	if got != want {
		return "", fmt.Errorf("%s: checksum %s does not match the release manifest %s", asset, got, want)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o755); err != nil {
			return "", err
		}
	}
	return filepath.Abs(path)
}

// gzipBody is a deterministic 4 KiB random payload, so every run compares
// the same bytes.
func gzipBody() []byte {
	raw := make([]byte, 4096)
	_, _ = rand.NewChaCha8([32]byte{42}).Read(raw)
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.ModTime = time.Unix(0, 0)
	_, _ = w.Write(raw)
	_ = w.Close()
	return buf.Bytes()
}

// compareOne drives one executable through the comparison commands against a
// fresh loopback HTTP server and returns the recorded outcomes.
func compareOne(ctx context.Context, label, executable, output string, body []byte) (map[string]any, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	plain := filepath.Join(output, label+"-gzip.pcap")
	mixed := filepath.Join(output, label+"-gzip-arp.pcap")
	response, err := writeCapture(plain, port, body, false)
	if err != nil {
		return nil, err
	}
	if _, err := writeCapture(mixed, port, body, true); err != nil {
		return nil, err
	}
	var requests atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var received []byte
				buf := make([]byte, 4096)
				for !bytes.Contains(received, []byte("\r\n\r\n")) && len(received) < 65536 {
					n, err := conn.Read(buf)
					received = append(received, buf[:n]...)
					if err != nil {
						return
					}
				}
				requests.Add(1)
				_, _ = conn.Write(response)
			}()
		}
	}()

	commands := []command{
		{"help", nil},
		{"gzip-inspection", []string{"check", plain, "-details"}},
		{"mixed-inspection", []string{"check", mixed, "-details"}},
	}
	replay := []string{"reproduce", plain, "-t", "127.0.0.1", "-report", filepath.Join(output, label+"-replay.json")}
	if label == "current" {
		// Historical binaries used reproduce for application replay. The current
		// command contract reserves reproduce for stateless captured packets.
		replay[0] = "live"
		commands = append(commands,
			command{"gzip-replay", replay},
			command{"selected-preview", []string{"live", mixed, "-session", "tcp-0", "-dry-run"}},
			command{"selected-replay", []string{"live", mixed, "-session", "tcp-0", "-t", "127.0.0.1", "-report", filepath.Join(output, "current-selected.json")}},
		)
	} else {
		commands = append(commands, command{"gzip-replay", append(replay, "-i", "comparison-no-packet-interface")})
	}
	outcomes := map[string]any{}
	for _, c := range commands {
		runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		out, runErr := exec.CommandContext(runCtx, executable, c.args...).CombinedOutput()
		cancel()
		if err := os.WriteFile(filepath.Join(output, label+"-"+c.name+".txt"), out, 0o644); err != nil {
			return nil, err
		}
		code := 0
		if runErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				return nil, fmt.Errorf("%s: %w", c.name, runErr)
			}
			code = exitErr.ExitCode()
		}
		sum := sha256.Sum256(out)
		outcomes[c.name] = map[string]any{"exitCode": code, "outputSHA256": hex.EncodeToString(sum[:])}
	}
	listener.Close()
	time.Sleep(50 * time.Millisecond)
	outcomes["localhostRequests"] = requests.Load()
	return outcomes, nil
}

// writeCapture writes the synthetic gzip HTTP exchange the release audit uses:
// a three-way handshake, one request, one response, and optionally a
// background ARP frame that the current build must be able to exclude.
func writeCapture(path string, port uint16, body []byte, background bool) ([]byte, error) {
	request := []byte("GET /download HTTP/1.1\r\nHost: device.local\r\n\r\n")
	response := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
	frames := [][]byte{
		frame(false, port, 100, 0, 2, nil),
		frame(true, port, 900, 101, 18, nil),
		frame(false, port, 101, 901, 16, nil),
		frame(false, port, 101, 901, 24, request),
		frame(true, port, 901, 101+uint32(len(request)), 24, response),
	}
	if background {
		arp, _ := hex.DecodeString("ffffffffffff02000000000108060001080006040001020000000001c000020a000000000000c0000214")
		frames = append(frames, arp)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], 1)
	if _, err := f.Write(header); err != nil {
		f.Close()
		return nil, err
	}
	for i, data := range frames {
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[0:], 1700000000)
		binary.LittleEndian.PutUint32(record[4:], uint32(1000*i))
		binary.LittleEndian.PutUint32(record[8:], uint32(len(data)))
		binary.LittleEndian.PutUint32(record[12:], uint32(len(data)))
		if _, err := f.Write(append(record, data...)); err != nil {
			f.Close()
			return nil, err
		}
	}
	return response, f.Close()
}

func checksum(data []byte) uint16 {
	if len(data)%2 == 1 {
		data = append(append([]byte(nil), data...), 0)
	}
	var total uint32
	for i := 0; i < len(data); i += 2 {
		total += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	for total>>16 != 0 {
		total = (total & 0xFFFF) + (total >> 16)
	}
	return ^uint16(total)
}

func frame(reverse bool, port uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	src, dst := []byte{192, 0, 2, 10}, []byte{192, 0, 2, 20}
	sport, dport := uint16(41000), port
	if reverse {
		src, dst, sport, dport = dst, src, dport, sport
	}
	eth, _ := hex.DecodeString("0200000000020200000000010800")
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(payload)))
	ip[8], ip[9] = 64, 6
	copy(ip[12:], src)
	copy(ip[16:], dst)
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12], tcp[13] = 0x50, flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	pseudo := append(append([]byte{}, src...), dst...)
	pseudo = append(pseudo, 0, 6)
	pseudo = binary.BigEndian.AppendUint16(pseudo, uint16(len(tcp)+len(payload)))
	binary.BigEndian.PutUint16(tcp[16:], checksum(append(append(pseudo, tcp...), payload...)))
	out := append(append(append([]byte{}, eth...), ip...), tcp...)
	return append(out, payload...)
}
