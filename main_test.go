package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
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

func TestParseWatchFlags(t *testing.T) {
	cfg, err := parseWatchFlags([]string{"-start", "10", "-batch-size", "5", "-debug", testLogURL})
	if err != nil {
		t.Fatalf("parseWatchFlags() error = %v, want nil", err)
	}
	if cfg.logURL != testLogURL || cfg.start != 10 || cfg.batchSize != 5 || !cfg.debug {
		t.Fatalf("parseWatchFlags() = %#v", cfg)
	}
}

func TestParseWatchFlagsRequiresSingleURL(t *testing.T) {
	tests := [][]string{
		nil,
		{testLogURL, "https://ct.example.net/log/ct/v1"},
	}

	for _, args := range tests {
		if _, err := parseWatchFlags(args); err == nil {
			t.Fatalf("parseWatchFlags(%#v) error = nil, want error", args)
		}
	}
}

func TestChromeWatchURLs(t *testing.T) {
	list := chromeLogList{
		Operators: []chromeLogOperator{
			{Logs: []chromeLog{
				{URL: " https://ct.example.com/log-a/ "},
				{URL: "https://ct.example.com/log-b/ct/v1"},
				{URL: ""},
			}},
		},
	}

	got := chromeWatchURLs(list)
	want := []string{
		"https://ct.example.com/log-a/ct/v1",
		"https://ct.example.com/log-b/ct/v1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chromeWatchURLs() = %#v, want %#v", got, want)
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
