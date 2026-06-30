package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
)

const (
	chromeLogListURL    = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	defaultStartBacklog = 2_000_000_000
)

type config struct {
	logURL    string
	start     int64
	batchSize int64
	debug     bool
}

type stream struct {
	client *http.Client
	out    io.Writer
	err    io.Writer
	debug  bool
}

type cliDeps struct {
	ctx    context.Context
	client *http.Client
	out    io.Writer
	errOut io.Writer
}

type rootOptions struct {
	List   listCommand   `command:"list" description:"List Chrome CT log URLs"`
	Stream streamCommand `command:"stream" description:"Stream a CT log"`
}

type listCommand struct {
	deps cliDeps
}

type streamCommand struct {
	Start     int64 `long:"start" default:"-1" description:"Entry index to start from; -1 starts from the default tail backlog"`
	BatchSize int64 `long:"batch-size" default:"3" description:"Number of entries to request per poll"`
	Debug     bool  `long:"debug" description:"Print retry and parse errors to stderr"`

	deps cliDeps
}

type sthResponse struct {
	TreeSize int64 `json:"tree_size"`
}

type entriesResponse struct {
	Entries []ctEntry `json:"entries"`
}

type ctEntry struct {
	LeafInput string `json:"leaf_input"`
}

type chromeLogList struct {
	Operators []chromeLogOperator `json:"operators"`
}

type chromeLogOperator struct {
	Logs []chromeLog `json:"logs"`
}

type chromeLog struct {
	URL   string                     `json:"url"`
	State map[string]json.RawMessage `json:"state"`
}

type chromeStreamLog struct {
	URL     string
	Retired bool
}

type tbsForAlgorithm struct {
	Raw              asn1.RawContent
	Version          int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber     asn1.RawValue
	Signature        pkix.AlgorithmIdentifier
	Issuer           asn1.RawValue
	Validity         asn1.RawValue
	Subject          asn1.RawValue
	SubjectPublicKey asn1.RawValue
	IssuerUniqueID   asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID  asn1.BitString   `asn1:"optional,tag:2"`
	Extensions       []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func main() {
	if err := runCLI(context.Background(), os.Args[1:], http.DefaultClient, os.Stdout, os.Stderr); err != nil {
		if flags.WroteHelp(err) {
			fmt.Fprint(os.Stdout, err)
			return
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(ctx context.Context, args []string, client *http.Client, out, errOut io.Writer) error {
	deps := cliDeps{ctx: ctx, client: client, out: out, errOut: errOut}
	opts := rootOptions{
		List:   listCommand{deps: deps},
		Stream: streamCommand{deps: deps},
	}
	parser := flags.NewNamedParser("ctlog-go", flags.Default&^flags.PrintErrors)
	parser.CommandHandler = func(command flags.Commander, args []string) error {
		if command == nil {
			return errors.New("usage: ctlog-go <list|stream>")
		}
		return command.Execute(args)
	}
	if _, err := parser.AddGroup("Commands", "", &opts); err != nil {
		return err
	}
	_, err := parser.ParseArgs(args)
	return err
}

func (c *listCommand) Execute(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: ctlog-go list")
	}
	return runList(c.deps.ctx, c.deps.client, c.deps.out)
}

func (c *streamCommand) Execute(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: ctlog-go stream [options] <ct-log-url>")
	}
	cfg := config{logURL: args[0], start: c.Start, batchSize: c.BatchSize, debug: c.Debug}
	return stream{client: c.deps.client, out: c.deps.out, err: c.deps.errOut, debug: c.Debug}.run(c.deps.ctx, cfg)
}

func runList(ctx context.Context, client *http.Client, out io.Writer) error {
	var list chromeLogList
	s := stream{client: client, out: out, err: io.Discard}
	if err := s.getJSON(ctx, chromeLogListURL, nil, &list); err != nil {
		return err
	}

	for _, log := range chromeStreamLogs(list) {
		fmt.Fprintln(out, formatChromeStreamLog(log))
	}
	return nil
}

func chromeStreamLogs(list chromeLogList) []chromeStreamLog {
	var logs []chromeStreamLog
	for _, operator := range list.Operators {
		for _, log := range operator.Logs {
			if streamURL := toStreamURL(log.URL); streamURL != "" {
				logs = append(logs, chromeStreamLog{URL: streamURL, Retired: log.isRetired()})
			}
		}
	}
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].URL < logs[j].URL
	})
	return logs
}

func (l chromeLog) isRetired() bool {
	_, ok := l.State["retired"]
	return ok
}

func formatChromeStreamLog(log chromeStreamLog) string {
	if log.Retired {
		return log.URL + " (retired)"
	}
	return log.URL
}

func toStreamURL(logURL string) string {
	logURL = strings.TrimRight(strings.TrimSpace(logURL), "/")
	if logURL == "" {
		return ""
	}
	if strings.HasSuffix(logURL, "/ct/v1") {
		return logURL
	}
	return logURL + "/ct/v1"
}

func (s stream) run(ctx context.Context, cfg config) error {
	logURL, err := normalizeLogURL(cfg.logURL)
	if err != nil {
		return err
	}
	if err := validateRange(cfg.start, -1, cfg.batchSize); err != nil {
		return err
	}

	fmt.Fprintf(s.out, "Connecting to CT log server: %s\n", logURL)

	var sth sthResponse
	if err := s.getJSON(ctx, logURL+"/get-sth", nil, &sth); err != nil {
		return err
	}
	if sth.TreeSize < 3 {
		return errors.New("tree_size is too small")
	}

	index := startIndex(cfg.start, sth.TreeSize)

	fmt.Fprintln(s.out, "Streaming started. Extracting domain names...")
	fmt.Fprintln(s.out)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entries, retry := s.fetchBatch(ctx, logURL, index, index+cfg.batchSize-1)
		if retry > 0 {
			sleepContext(ctx, retry)
			continue
		}

		for _, entry := range entries {
			s.printEntry(logURL, index, entry)
			index++
		}
		if len(entries) == 0 {
			sleepContext(ctx, 300*time.Millisecond)
		}
	}
}

func startIndex(start, treeSize int64) int64 {
	if start >= 0 {
		return start
	}
	index := treeSize - defaultStartBacklog
	if index < 0 {
		return 0
	}
	return index
}

func (s stream) fetchBatch(ctx context.Context, logURL string, start, end int64) ([]ctEntry, time.Duration) {
	var body entriesResponse
	params := url.Values{"start": {fmt.Sprint(start)}, "end": {fmt.Sprint(end)}}
	err := s.getJSON(ctx, logURL+"/get-entries", params, &body)
	if err == nil {
		return body.Entries, 0
	}

	var httpErr httpStatusError
	if errors.As(err, &httpErr) && httpErr.status == http.StatusBadRequest {
		s.debugf("get-entries start=%d end=%d: %v", start, end, err)
		return nil, 500 * time.Millisecond
	}
	s.debugf("get-entries start=%d end=%d: %v", start, end, err)
	return nil, time.Second
}

func (s stream) printEntry(logURL string, index int64, entry ctEntry) {
	if entry.LeafInput == "" {
		s.debugf("entry %d: missing leaf_input", index)
		return
	}

	domains, err := parseDomainsFromEntry(entry.LeafInput)
	if err != nil {
		s.debugf("entry %d: %v", index, err)
		return
	}
	if len(domains) > 0 {
		fmt.Fprintf(s.out, "[%d] %s - %s\n", index, displayLogURL(logURL), strings.Join(domains, ", "))
	}
}

func displayLogURL(logURL string) string {
	return strings.TrimSuffix(logURL, "/ct/v1") + "/"
}

func (s stream) getJSON(ctx context.Context, rawURL string, params url.Values, v any) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if params != nil {
		u.RawQuery = params.Encode()
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return httpStatusError{status: resp.StatusCode, url: u.String()}
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (s stream) debugf(format string, args ...any) {
	if s.debug {
		fmt.Fprintf(s.err, "[debug] "+format+"\n", args...)
	}
}

type httpStatusError struct {
	status int
	url    string
}

func (e httpStatusError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d", e.url, e.status)
}

func validateRange(start, minStart, batchSize int64) error {
	if batchSize < 1 {
		return errors.New("batch-size must be greater than 0")
	}
	if start < minStart {
		return fmt.Errorf("start must be %d or greater", minStart)
	}
	return nil
}

func normalizeLogURL(logURL string) (string, error) {
	logURL = strings.TrimRight(strings.TrimSpace(logURL), "/")
	if logURL == "" {
		return "", errors.New("log-url is empty")
	}

	u, err := url.Parse(logURL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("log-url must start with http:// or https://")
	}
	if u.Host == "" {
		return "", errors.New("log-url host is empty")
	}
	return logURL, nil
}

func parseDomainsFromEntry(leafInputB64 string) ([]string, error) {
	leaf, err := base64.StdEncoding.DecodeString(leafInputB64)
	if err != nil {
		return nil, fmt.Errorf("decode leaf_input: %w", err)
	}
	if len(leaf) < 15 {
		return nil, fmt.Errorf("leaf_input too short: %d bytes", len(leaf))
	}

	switch typ := binary.BigEndian.Uint16(leaf[10:12]); typ {
	case 0:
		return domainsFromCertificate(readVarBytes(leaf, 12, 15))
	case 1:
		return domainsFromCertificate(wrapTBSCertificate(readVarBytes(leaf, 44, 47)))
	default:
		return nil, fmt.Errorf("unsupported entry type: %d", typ)
	}
}

func readVarBytes(b []byte, lenStart, dataStart int) []byte {
	if len(b) < dataStart {
		return nil
	}
	n := uint24(b[lenStart:dataStart])
	if n > len(b)-dataStart {
		return nil
	}
	return b[dataStart : dataStart+n]
}

func domainsFromCertificate(der []byte) ([]string, error) {
	if len(der) == 0 {
		return nil, errors.New("empty or truncated certificate")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	domains := map[string]struct{}{}
	add(domains, cert.Subject.CommonName)
	for _, name := range cert.DNSNames {
		add(domains, name)
	}
	return sortedDomains(domains), nil
}

func wrapTBSCertificate(tbs []byte) []byte {
	if len(tbs) == 0 {
		return nil
	}
	var parsed tbsForAlgorithm
	if _, err := asn1.Unmarshal(tbs, &parsed); err != nil {
		return nil
	}
	cert := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{FullBytes: tbs},
		SignatureAlgorithm: parsed.Signature,
		SignatureValue:     asn1.BitString{Bytes: []byte{0}, BitLength: 1},
	}
	der, _ := asn1.Marshal(cert)
	return der
}

func add(domains map[string]struct{}, domain string) {
	if domain != "" {
		domains[domain] = struct{}{}
	}
}

func sortedDomains(domains map[string]struct{}) []string {
	result := make([]string, 0, len(domains))
	for domain := range domains {
		result = append(result, domain)
	}
	sort.Strings(result)
	return result
}

func uint24(b []byte) int {
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

func sleepContext(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
