# rdp-screenshotter-go

Pure-Go RDP client built for one job: open an RDP connection, walk the
protocol all the way to the first server bitmap update, and dump it to a PNG.
No cgo, no FreeRDP shell-out, no XServer.

```
go install github.com/x-stp/rdp-screenshotter-go/cmd/rdp-screenshotter@latest
echo 1.2.3.4:3389 > targets.txt
rdp-screenshotter -targets targets.txt -workers 8 -output screenshots/
```

Against an arbitrary slice of public Windows servers (a fresh Shodan
`port:3389 has_screenshot:true` dump), restricted to the hosts that negotiate
without NLA, it captures roughly **86%** — from Server 2008 through Server
2022 and Windows 10/11. Standard RDP Security, TLS-only, and modern
Server 2012R2+ hosts all work; NLA-required servers work when you supply
`-username` / `-password` / `-domain` (NTLMv2 or, with `-kerberos`, an AP-REQ
from your credential cache).

> Getting the modern-server tier working hinged on emitting a coherent
> `TS_UD_CS_CORE` ([MS-RDPBCGR] §2.2.1.3.2): Server 2012R2+ RST the
> connection right after MCS Connect Initial if the color-depth / capability
> fields don't line up, where Server 2008 accepts almost anything.

## CLI

```
rdp-screenshotter [flags]

  -targets       file with one host[:port] per line, # comments allowed (default "target.txt")
  -output        directory to drop PNGs into, created if missing      (default "screenshots")
  -workers       concurrent connections                                (default 5)
  -timeout       per-connection wall budget (hard cap is 3x this)      (default 10s)
  -username      RDP cookie / NLA username                             (optional)
  -password      NLA password (enables HYBRID negotiation)             (optional)
  -domain        NLA / Kerberos realm                                  (optional)
  -log-level     trace|debug|info|warn|error                           (default warn)
  -anonymous     offer PROTOCOL_HYBRID + run anonymous CredSSP/NTLMv2  (off by default)
  -kerberos      advertise Kerberos V5 in CredSSP, fall back to NTLM   (off by default)
  -krb5-ccache   Kerberos credential cache path ($KRB5CCNAME default)  (optional)
  -krb5-config   krb5.conf path ($KRB5_CONFIG default)                 (optional)
  -output-format text | json per-target result lines                  (default text)
```

`-anonymous` is the trick Shodan and similar mass-scanners use to paint the
lock screen on NLA-required Windows. It runs the CredSSP/NTLMSSP exchange
with the [MS-NLMP] §3.1.5.1.2 anonymous AUTHENTICATE_MESSAGE (1-byte 0x00
LmChallengeResponse, empty NtChallengeResponse, zero session key); if the
server's GINA renders the lock screen before tearing down the channel we get
a one-shot capture. Trade-off: forcing HYBRID into the X.224 NegReq makes
modern Windows hosts that would otherwise have answered with PROTOCOL_RDP or
PROTOCOL_SSL pick HYBRID instead, and most of them have NTLM disabled at the
SSPI layer (`SEC_E_INVALID_TOKEN`), so the captured-host count drops. Use
`-anonymous` when you specifically need NLA-gated targets and don't mind
losing the legacy-NLA-off ones in the same run.

`-kerberos` runs the CredSSP exchange with an RFC 4121 GSS-Kerberos AP-REQ
(SPN `TERMSRV/<host>`) built from your credential cache — populate it with
`kinit` first. Any Kerberos failure (no ccache, KDC unreachable, KRB-ERROR)
transparently falls back to the NTLM path, so the flag is safe to leave on
for mixed AD / standalone runs.

`-output-format json` emits one JSON object per target on stdout
(`{"index","total","target","status","file","error","duration_ms"}`) so
results pipe straight into `jq`. `text` (default) is the human-readable
`[n/total] OK host -> file` form.

`screenshots/HOST_PORT.png` is written for every successful capture. Per-target
result lines go to **stdout**; protocol logs go to **stderr** at the level you
pick. Pipe stdout to a file, leave stderr on the terminal. No single host can
pin a worker: each target is capped at 3x `-timeout` by a watchdog that closes
the connection on expiry.

## Library

The whole thing is also usable as a library:

```go
package main

import (
    "fmt"
    "os"
    "time"

    "github.com/rs/zerolog"
    "github.com/x-stp/rdp-screenshotter-go/pkg/rdp"
)

func main() {
    rdp.SetLogLevel(zerolog.InfoLevel)

    client, err := rdp.NewClient("1.2.3.4:3389", &rdp.ClientOptions{
        Timeout: 15 * time.Second,
    })
    if err != nil { panic(err) }
    defer client.Close()

    png, err := client.Screenshot()
    if err != nil { panic(err) }
    _ = os.WriteFile("shot.png", png, 0o644)
    fmt.Printf("captured %d bytes\n", len(png))
}
```

`rdp.SetLogger(zerolog.Nop())` silences the package entirely. `rdp.SetLogger`,
`rdp.SetLogOutput` and `rdp.SetLogLevel` are the only knobs the library
exposes for logging.

## Architecture

```
cmd/rdp-screenshotter/   concurrent CLI worker pool around pkg/rdp
cmd/credssp-test/        single-target NLA diagnostic harness
pkg/rdp/                 RDP protocol implementation
  client.go              Client + ClientOptions, Screenshot() orchestration
  connect.go             X.224 + TLS + CredSSP handshake, MCS domain join,
                         Demand/Confirm Active, Client Info PDU
  secure.go              Standard RDP MAC + RC4 wrap, basic security header
  read.go                slow/fast-path receive, reactivation, bitmap compositing
  log.go                 package zerolog.Logger + level helpers
  tpkt.go                RFC 1006 packet framing
  x224.go                ITU-T X.224 connection negotiation + neg failure retry
  mcs.go                 T.125 MCS channel management, GCC client/server data
  per/per.go             ITU-T X.691 PER primitives (+ round-trip tests)
  security.go            session key derivation, raw-RSA exchange, MAC, RC4
  credssp.go             CredSSP/NLA orchestration: TSRequest, SPNEGO (MS-CSSP)
  ntlm.go                NTLMv2 negotiate/authenticate/seal (MS-NLMP)
  kerberos.go            GSS-Kerberos AP-REQ via gokrb5 (RFC 4121 in MS-CSSP)
  spnego.go              SPNEGO token wrapping (RFC 4178)
  pdu.go                 share control / share data PDU builders + parsers
  capabilities.go        Confirm Active capability negotiation
  licensing.go           licensing PDU dispatch + STATUS_VALID_CLIENT alert
  license_protocol.go    full NEW_LICENSE_REQUEST / PLATFORM_CHALLENGE_RESPONSE
                         dance per [MS-RDPELE]
  tls.go                 TLS upgrade via zcrypto/tls
pkg/bitmap/              bitmap pixel decoders
  bitmap.go              15/16/24/32 bpp -> PNG, bottom-up DIB row flip
  rle.go                 RDP RLE bitmap decompressor (MS-RDPBCGR §3.1.9)
```

## Protocol coverage

| Feature                                 | Status |
|-----------------------------------------|--------|
| X.224 negotiation + RDP_NEG_FAILURE retry | works |
| Modern-server MCS activation (Server 2012R2 .. 2022, Win10/11) | works |
| Deactivate-All / reactivation sequence   | works |
| Standard RDP security (RC4, 40/56/128-bit) | works |
| Server X.509 chain + proprietary cert     | works |
| TLS-only transport                       | works |
| NLA / CredSSP via NTLMv2 + SPNEGO        | works |
| Kerberos via CredSSP (AP-REQ, NTLM fallback) | works |
| Full RDP licensing (NEW_LICENSE_REQUEST, PLATFORM_CHALLENGE_RESPONSE) | works |
| Slow-path bitmap updates (15/16/24/32 bpp) | works |
| Fast-path output PDUs                    | works |
| Bitmap RLE decompression                 | works |
| RemoteFX / Graphics Pipeline (RDPGFX)    | not implemented |
| Dynamic virtual channels                 | not implemented |

## Specifications referenced

- [MS-RDPBCGR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/) -- RDP Basic Connectivity & Graphics Remoting
- [MS-RDPELE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/) -- RDP Licensing Extension
- [MS-CSSP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/) -- CredSSP
- [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/) -- NTLM
- [ITU-T T.125](https://www.itu.int/rec/T-REC-T.125) / [T.124](https://www.itu.int/rec/T-REC-T.124) -- MCS / GCC
- [ITU-T X.224](https://www.itu.int/rec/T-REC-X.224) / [X.691](https://www.itu.int/rec/T-REC-X.691) -- COTP / PER
- [RFC 1006](https://www.rfc-editor.org/rfc/rfc1006) -- TPKT over TCP
- [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178) (SPNEGO) / [RFC 4121](https://www.rfc-editor.org/rfc/rfc4121) (GSS-Kerberos)
- [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) (TLS 1.2) / [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) (SNI)

## Building / testing

```
make build      # or: go build ./...
make test       # go test -race ./...
make lint       # go vet + golangci-lint (config in .golangci.yml)
```

Requires Go 1.25+. The package works around Go's `crypto/rsa`
minimum-key-size guard explicitly, since RDP Standard Security exchange keys
are 512-bit ([MS-RDPBCGR] §5.3.4).

See [TODO.md](TODO.md) for known limitations and the next slice of work.
