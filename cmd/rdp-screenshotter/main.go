// Command rdp-screenshotter captures PNG screenshots of public RDP servers in
// parallel.
//
// Usage:
//
//	rdp-screenshotter [flags]
//
// Flags:
//
//	-targets    file with one host[:port] per line (# comments allowed)
//	-output     directory to drop PNGs into (created if missing)
//	-workers    number of concurrent connections to maintain
//	-timeout    per-connection wall budget
//	-username   RDP cookie / NLA username, optional
//	-password   NLA password, optional (enables HYBRID negotiation)
//	-domain     NLA domain, optional
//	-log-level     zerolog level: trace|debug|info|warn|error (default: warn)
//	-output-format text|json per-target progress format on stdout
//
// The default log level is `warn` so the per-target progress emitted by main
// stays clean. Crank it to `info` or `debug` to see the full RDP/MCS/license
// flow on stderr.
//
// In `-output-format json` mode each per-target line on stdout is a single
// JSON object so it's `jq`-friendly:
//
//	{"index":3,"total":100,"target":"1.2.3.4:3389","status":"ok","file":"...","duration_ms":4123}
//	{"index":4,"total":100,"target":"5.6.7.8:3389","status":"err","error":"connect: ...","duration_ms":1002}
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/x-stp/rdp-screenshotter-go/pkg/rdp"
)

const (
	outputFormatText = "text"
	outputFormatJSON = "json"
)

func main() {
	cfg := parseFlags()
	configureLogger(cfg.logLevel)

	targets, err := readTargets(cfg.targetFile)
	if err != nil {
		fail("read targets: %v", err)
	}
	if len(targets) == 0 {
		fail("no targets in %s", cfg.targetFile)
	}
	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		fail("create output dir: %v", err)
	}

	fmt.Fprintf(os.Stderr, "shooting %d targets with %d workers, timeout %s\n",
		len(targets), cfg.workers, cfg.timeout)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	results := runWorkers(ctx, cfg, targets)
	summarise(results, len(targets), cfg.outputFormat)
}

type config struct {
	targetFile     string
	outputDir      string
	workers        int
	timeout        time.Duration
	username       string
	password       string
	domain         string
	logLevel       string
	anonymous      bool
	outputFormat   string
	kerberos       bool
	kerberosCCache string
	kerberosConfig string
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.targetFile, "targets", "target.txt", "file with one host[:port] per line")
	flag.StringVar(&cfg.outputDir, "output", "screenshots", "output directory for PNGs")
	flag.IntVar(&cfg.workers, "workers", 5, "concurrent connections")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-connection timeout")
	flag.StringVar(&cfg.username, "username", "", "RDP cookie / NLA username")
	flag.StringVar(&cfg.password, "password", "", "NLA password")
	flag.StringVar(&cfg.domain, "domain", "", "NLA / Kerberos realm (upper-case)")
	flag.StringVar(&cfg.logLevel, "log-level", "warn", "log level: trace|debug|info|warn|error")
	flag.BoolVar(&cfg.anonymous, "anonymous", false, "offer PROTOCOL_HYBRID and run anonymous CredSSP for NLA-gated hosts")
	flag.StringVar(&cfg.outputFormat, "output-format", outputFormatText, "per-target progress format: text|json")
	flag.BoolVar(&cfg.kerberos, "kerberos", false, "advertise Kerberos V5 in CredSSP (needs $KRB5CCNAME or -krb5-ccache); falls back to NTLM on failure")
	flag.StringVar(&cfg.kerberosCCache, "krb5-ccache", "", "path to Kerberos credential cache (default: $KRB5CCNAME or /tmp/krb5cc_<uid>)")
	flag.StringVar(&cfg.kerberosConfig, "krb5-config", "", "path to krb5.conf (default: $KRB5_CONFIG or /etc/krb5.conf)")
	flag.Parse()
	if cfg.outputFormat != outputFormatText && cfg.outputFormat != outputFormatJSON {
		fail("invalid -output-format %q (want text|json)", cfg.outputFormat)
	}
	return cfg
}

func configureLogger(level string) {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		fail("invalid -log-level %q: %v", level, err)
	}
	rdp.SetLogLevel(lvl)
}

type result struct {
	target   string
	file     string
	err      error
	duration time.Duration
}

func runWorkers(ctx context.Context, cfg config, targets []string) <-chan result {
	out := make(chan result)
	jobs := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < cfg.workers; i++ {
		wg.Go(func() {
			for target := range jobs {
				start := time.Now()
				file, err := captureOne(ctx, target, cfg)
				select {
				case out <- result{target: target, file: file, err: err, duration: time.Since(start)}:
				case <-ctx.Done():
					return
				}
			}
		})
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(out) }()
	return out
}

func captureOne(ctx context.Context, target string, cfg config) (string, error) {
	opts := &rdp.ClientOptions{
		Timeout:        cfg.timeout,
		Username:       cfg.username,
		Password:       cfg.password,
		Domain:         cfg.domain,
		AnonymousNLA:   cfg.anonymous,
		Kerberos:       cfg.kerberos,
		KerberosCCache: cfg.kerberosCCache,
		KerberosConfig: cfg.kerberosConfig,
	}

	// Absolute per-target wall-clock cap. The client's dialer, activation
	// loop and bitmap read each carry their own net.Conn deadlines, but a
	// pathological server can chain enough legal-but-slow PDUs to keep a
	// worker busy well past -timeout. Closing the conn from a watchdog
	// unblocks any in-flight Read so no single host can pin a worker.
	deadline := 3 * cfg.timeout
	tctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	client, err := rdp.NewClient(target, opts)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-tctx.Done():
			client.Close() // unblocks the in-flight Read in Screenshot
		case <-stopped:
		}
	}()

	img, err := client.Screenshot()
	if err != nil {
		if tctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timeout after %s", deadline)
		}
		return "", fmt.Errorf("screenshot: %w", err)
	}

	file := filepath.Join(cfg.outputDir, sanitiseHost(target)+".png")
	if err := os.WriteFile(file, img, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", file, err)
	}
	return file, nil
}

// jsonResult is the per-target object emitted on stdout in -output-format json
// mode. Keep field order stable for downstream `jq` pipelines.
type jsonResult struct {
	Index      int    `json:"index"`
	Total      int    `json:"total"`
	Target     string `json:"target"`
	Status     string `json:"status"` // "ok" | "err"
	File       string `json:"file,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

func summarise(results <-chan result, total int, format string) {
	var ok, failed atomic.Int64
	enc := json.NewEncoder(os.Stdout)
	idx := 0
	for r := range results {
		idx++
		if r.err == nil {
			ok.Add(1)
		} else {
			failed.Add(1)
		}
		switch format {
		case outputFormatJSON:
			out := jsonResult{
				Index:      idx,
				Total:      total,
				Target:     r.target,
				DurationMS: r.duration.Milliseconds(),
			}
			if r.err == nil {
				out.Status = "ok"
				out.File = r.file
			} else {
				out.Status = "err"
				out.Error = r.err.Error()
			}
			_ = enc.Encode(out)
		default:
			if r.err == nil {
				fmt.Printf("[%d/%d] OK  %s -> %s\n", idx, total, r.target, r.file)
			} else {
				fmt.Printf("[%d/%d] ERR %s: %s\n", idx, total, r.target, r.err)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d successful, %d failed\n", ok.Load(), failed.Load())
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var out []string
	for raw := range strings.SplitSeq(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, ":") {
			line = net.JoinHostPort(line, "3389")
		}
		out = append(out, line)
	}
	return out, nil
}

// sanitiseHost turns "1.2.3.4:3389" into "1.2.3.4_3389" so it's filesystem-safe.
func sanitiseHost(s string) string {
	r := strings.NewReplacer(":", "_", "/", "_", "\\", "_")
	return r.Replace(s)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rdp-screenshotter: "+format+"\n", args...)
	os.Exit(1)
}
