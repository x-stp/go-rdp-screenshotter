// Command credssp-test exercises the CredSSP/NLA path of pkg/rdp against a
// single server. It is purely a diagnostic harness, not a screenshot tool.
//
// Usage:
//
//	credssp-test -target HOST:PORT [-username USER] [-password PASS] [-domain DOM]
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/x-stp/rdp-screenshotter-go/pkg/rdp"
)

func main() {
	var (
		target   = flag.String("target", "", "host:port of the RDP server")
		username = flag.String("username", "", "NLA username")
		password = flag.String("password", "", "NLA password")
		domain   = flag.String("domain", "", "NLA domain")
		timeout  = flag.Duration("timeout", 30*time.Second, "connection timeout")
		logLevel = flag.String("log-level", "debug", "trace|debug|info|warn|error")
	)
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "usage: credssp-test -target HOST:PORT [-username U] [-password P] [-domain D]")
		os.Exit(2)
	}
	if lvl, err := zerolog.ParseLevel(*logLevel); err == nil {
		rdp.SetLogLevel(lvl)
	}

	opts := &rdp.ClientOptions{
		Timeout:  *timeout,
		Username: *username,
		Password: *password,
		Domain:   *domain,
	}
	client, err := rdp.NewClient(*target, opts)
	if err != nil {
		fail("X.224 connect: %v", err)
	}
	defer client.Close()

	fmt.Fprintf(os.Stderr, "negotiated protocol: 0x%08x (tls=%v)\n",
		client.GetNegotiatedProtocol(), client.IsTLSEnabled())

	if !client.IsTLSEnabled() {
		host, _, _ := net.SplitHostPort(*target)
		if err := client.UpgradeTLS(rdp.DefaultTLSConfig(host)); err != nil {
			fail("TLS upgrade: %v", err)
		}
	}

	if err := client.TestCredSSPAuth(); err != nil {
		fail("CredSSP: %v", err)
	}
	fmt.Fprintln(os.Stderr, "CredSSP OK")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "credssp-test: "+format+"\n", args...)
	os.Exit(1)
}
