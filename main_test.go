package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jessevdk/go-flags"
)

const testLogURL = "https://ct.example.com/log/ct/v1"

func TestNormalizeLogURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "default",
			input: testLogURL,
			want:  testLogURL,
		},
		{
			name:  "trims whitespace and trailing slash",
			input: " https://example.com/log/ct/v1/ ",
			want:  "https://example.com/log/ct/v1",
		},
		{
			name:    "empty",
			input:   " ",
			wantErr: true,
		},
		{
			name:    "missing scheme",
			input:   "example.com/log/ct/v1",
			wantErr: true,
		},
		{
			name:    "missing host",
			input:   "https:///ct/v1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeLogURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeLogURL() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeLogURL() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeLogURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStreamCommandParsesLongOptions(t *testing.T) {
	cmd := streamCommand{}
	parser := flags.NewParser(&cmd, flags.Default&^flags.PrintErrors)
	args, err := parser.ParseArgs([]string{"--start", "10", "--batch-size", "5", "--debug", testLogURL})
	if err != nil {
		t.Fatalf("ParseArgs() error = %v, want nil", err)
	}
	if !reflect.DeepEqual(args, []string{testLogURL}) {
		t.Fatalf("ParseArgs() args = %#v, want %#v", args, []string{testLogURL})
	}
	if cmd.Start != 10 || cmd.BatchSize != 5 || !cmd.Debug {
		t.Fatalf("streamCommand = %#v", cmd)
	}
}

func TestStreamCommandRejectsShortStyleOptions(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "start", args: []string{"-start", "10", testLogURL}},
		{name: "batch size", args: []string{"-batch-size", "5", testLogURL}},
		{name: "debug", args: []string{"-debug", testLogURL}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := runCLI(context.Background(), append([]string{"stream"}, tt.args...), http.DefaultClient, io.Discard, io.Discard); err == nil {
				t.Fatalf("runCLI(%#v) error = nil, want error", tt.args)
			}
		})
	}
}

func TestRunCLICommandErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no command"},
		{name: "unknown command", args: []string{"unknown"}},
		{name: "list rejects extra args", args: []string{"list", testLogURL}},
		{name: "stream requires URL", args: []string{"stream"}},
		{name: "stream rejects extra URL", args: []string{"stream", testLogURL, "https://ct.example.net/log/ct/v1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := runCLI(context.Background(), tt.args, http.DefaultClient, io.Discard, io.Discard); err == nil {
				t.Fatalf("runCLI(%#v) error = nil, want error", tt.args)
			}
		})
	}
}

func TestChromeStreamLogs(t *testing.T) {
	list := chromeLogList{
		Operators: []chromeLogOperator{
			{Logs: []chromeLog{
				{URL: " https://ct.example.com/log-a/ "},
				{
					URL:   "https://ct.example.com/log-b/ct/v1",
					State: map[string]json.RawMessage{"retired": json.RawMessage(`{"timestamp":"1234"}`)},
				},
				{URL: ""},
			}},
		},
	}

	got := chromeStreamLogs(list)
	want := []chromeStreamLog{
		{URL: "https://ct.example.com/log-a/ct/v1"},
		{URL: "https://ct.example.com/log-b/ct/v1", Retired: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chromeStreamLogs() = %#v, want %#v", got, want)
	}
}

func TestFormatChromeStreamLog(t *testing.T) {
	tests := []struct {
		name string
		log  chromeStreamLog
		want string
	}{
		{
			name: "active",
			log:  chromeStreamLog{URL: "https://ct.example.com/log/ct/v1"},
			want: "https://ct.example.com/log/ct/v1",
		},
		{
			name: "retired",
			log:  chromeStreamLog{URL: "https://ct.example.com/log/ct/v1", Retired: true},
			want: "https://ct.example.com/log/ct/v1 (retired)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatChromeStreamLog(tt.log); got != tt.want {
				t.Fatalf("formatChromeStreamLog() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
	}{
		{
			name: "invalid batch size",
			cfg:  config{logURL: testLogURL, batchSize: 0, start: -1},
		},
		{
			name: "invalid start",
			cfg:  config{logURL: testLogURL, batchSize: 3, start: -2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := stream{client: http.DefaultClient, out: io.Discard, err: io.Discard}
			if err := s.run(context.Background(), tt.cfg); err == nil {
				t.Fatalf("run() error = nil, want error")
			}
		})
	}
}

func TestStartIndex(t *testing.T) {
	tests := []struct {
		name     string
		start    int64
		treeSize int64
		want     int64
	}{
		{name: "explicit start", start: 123, treeSize: 3_000_000_000, want: 123},
		{name: "default tail backlog", start: -1, treeSize: 2_650_546_745, want: 650_546_745},
		{name: "small tree starts at zero", start: -1, treeSize: 100, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startIndex(tt.start, tt.treeSize); got != tt.want {
				t.Fatalf("startIndex() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDebugf(t *testing.T) {
	var buf strings.Builder
	stream{err: &buf, debug: true}.debugf("entry %d: %s", 12, "bad")
	if got, want := buf.String(), "[debug] entry 12: bad\n"; got != want {
		t.Fatalf("debugf() wrote %q, want %q", got, want)
	}

	buf.Reset()
	stream{err: &buf}.debugf("hidden")
	if buf.Len() != 0 {
		t.Fatalf("debugf() wrote %q with debug disabled, want empty", buf.String())
	}
}

func TestParseDomainsFromEntry(t *testing.T) {
	certDER := testCertificateDER(t, "example.com", []string{"www.example.com", "example.com"})
	leafInput := testLeafInput(0, certDER)

	got, err := parseDomainsFromEntry(base64.StdEncoding.EncodeToString(leafInput))
	if err != nil {
		t.Fatalf("parseDomainsFromEntry() error = %v, want nil", err)
	}
	want := []string{"example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDomainsFromEntry() = %#v, want %#v", got, want)
	}
}

func TestParseDomainsFromPrecertEntry(t *testing.T) {
	certDER := testCertificateDER(t, "example.org", []string{"www.example.org", "example.org"})
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	leafInput := testPrecertLeafInput(cert.RawTBSCertificate)
	got, err := parseDomainsFromEntry(base64.StdEncoding.EncodeToString(leafInput))
	if err != nil {
		t.Fatalf("parseDomainsFromEntry() error = %v, want nil", err)
	}
	want := []string{"example.org", "www.example.org"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDomainsFromEntry() = %#v, want %#v", got, want)
	}
}

func TestParseDomainsFromEntryMalformedInputs(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "invalid base64", input: "%%%"},
		{name: "too short", input: base64.StdEncoding.EncodeToString([]byte{1, 2, 3})},
		{name: "unsupported entry type", input: base64.StdEncoding.EncodeToString(testLeafInput(2, []byte{1, 2, 3}))},
		{name: "truncated certificate", input: base64.StdEncoding.EncodeToString([]byte{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0,
			0, 0, 3,
			1,
		})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDomainsFromEntry(tt.input)
			if err == nil {
				t.Fatalf("parseDomainsFromEntry() error = nil, want error")
			}
			if len(got) != 0 {
				t.Fatalf("parseDomainsFromEntry() = %#v, want empty result", got)
			}
		})
	}
}

func TestPrintEntryIncludesLogURL(t *testing.T) {
	certDER := testCertificateDER(t, "gestancias.com", []string{"www.gestancias.com", "gestancias.com"})
	entry := ctEntry{LeafInput: base64.StdEncoding.EncodeToString(testLeafInput(0, certDER))}

	var buf strings.Builder
	stream{out: &buf, err: io.Discard}.printEntry("https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1", 650546745, entry)

	want := "[650546745] https://ct.googleapis.com/logs/us1/argon2026h1/ - gestancias.com, www.gestancias.com\n"
	if got := buf.String(); got != want {
		t.Fatalf("printEntry() wrote %q, want %q", got, want)
	}
}

func TestDisplayLogURL(t *testing.T) {
	if got, want := displayLogURL(testLogURL), "https://ct.example.com/log/"; got != want {
		t.Fatalf("displayLogURL() = %q, want %q", got, want)
	}
}

func testCertificateDER(t *testing.T, commonName string, dnsNames []string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func testLeafInput(entryType uint16, certDER []byte) []byte {
	leaf := make([]byte, 15+len(certDER))
	leaf[10] = byte(entryType >> 8)
	leaf[11] = byte(entryType)
	leaf[12] = byte(len(certDER) >> 16)
	leaf[13] = byte(len(certDER) >> 8)
	leaf[14] = byte(len(certDER))
	copy(leaf[15:], certDER)
	return leaf
}

func testPrecertLeafInput(tbsCertificate []byte) []byte {
	leaf := make([]byte, 47+len(tbsCertificate))
	leaf[11] = 1
	leaf[44] = byte(len(tbsCertificate) >> 16)
	leaf[45] = byte(len(tbsCertificate) >> 8)
	leaf[46] = byte(len(tbsCertificate))
	copy(leaf[47:], tbsCertificate)
	return leaf
}
