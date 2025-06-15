# TODO

Tracking the remaining gaps in `pkg/rdp` ranked by how much real-world coverage
they unlock.

## Protocol gaps that still cost us screenshots

- **Kerberos via CredSSP.** Only NTLMv2 is wired up. Servers that require
  Kerberos (Active Directory bound, no fallback) reject our HYBRID handshake
  during NLA. Implementing GSS-Kerberos under SPNEGO is a sizeable lift but
  unlocks every domain-bound Windows host. See `pkg/rdp/credssp.go` and
  `pkg/rdp/spnego.go`.

- **Per-target wall-clock cap.** A single target can still pin a worker past
  its deadlines (observed once in a 957-target run): the connect dialer and
  the bitmap read loop each have deadlines, but the licensing / activation
  loop can chain several 10s reads. Add one overall `context.WithTimeout`
  around `Screenshot()` in the worker so no target exceeds, say, 2x the CLI
  `-timeout`.

- **Graphics Pipeline / RemoteFX-only servers.** Hosts *configured* to
  disable slow/fast-path bitmap updates and only emit `RDPGFX_*` over a
  dynamic virtual channel still produce a blank canvas. This is now a small
  slice: with the CS_CORE fix below, ordinary Server 2019/2022 + Win10/11
  hosts fall back to bitmap updates and capture fine (~86% of reachable
  non-NLA hosts in a 957-target sample). Full GFX still needs:
  1. Dynamic virtual channel (DVC) plumbing in `pkg/rdp/mcs.go`.
  2. A `pkg/rdp/gfx.go` decoder for `RDPGFX_PDU_*` (MS-RDPEGFX), specifically
     `WIRE_TO_SURFACE_PDU_1/2`, `SURFACE_COMMAND` framing, and the H.264 +
     ClearCodec + RemoteFX-progressive codecs riding on top.

- **Dynamic virtual channels generally.** `drdynvc` opens up auto-detect
  responses, multitransport, and the GFX channel above. Same `mcs.go`
  plumbing, plus `pkg/rdp/dvc.go`.

- **Persistent license cache.** We re-do the full
  `NEW_LICENSE_REQUEST -> PLATFORM_CHALLENGE_RESPONSE` dance on every
  connection because we never persist `SERVER_NEW_LICENSE`. Caching the
  issued license + a stable hardware ID would shave one round-trip and stop
  servers from ratcheting their license counters.

  *Status:* deferred. Implementing the wire side (decrypt
  `NEW_LICENSE.EncryptedLicenseInfo` with the per-connection
  `LicensingEncryptionKey`, persist the decrypted `LICENSE_INFO`, re-encrypt
  with the next connection's key, send as `CLIENT_LICENSE_INFO` per
  [MS-RDPELE] §2.2.2.6) requires a real Per-Device-CAL Windows licensing
  server to cross-check against. Shipping unprovable crypto code is worse
  than shipping nothing. The current `handleLicenseRequest` already
  short-circuits to `STATUS_VALID_CLIENT` when anything in the new-license
  dance fails, so most public targets never consume a CAL anyway.

## Code-quality follow-ups

- `pkg/bitmap/rle.go` -- the three decoders (decompress1/2/3) share opcode
  logic but have type-specific XOR/store paths (byte / uint16 / [3]uint8)
  that don't generic-flatten cleanly without an interface-dispatch overhead
  per pixel. decompress4 uses the wholly different RDP 6.0 plane encoding
  and shares nothing. Deferred: the 10 golden tests in `rle_test.go` pin
  byte-level behaviour, so the wins from collapsing the file are cosmetic
  while the regression risk (e.g. the SPECIAL_FGBG_1/_2 mixmask issue
  below) is real.

- The grdp port's `decompress*()` SPECIAL_FGBG_1/_2 handling appears to lose
  the per-bit `mixmask` ratchet relative to FreeRDP. Worth a side-by-side
  reread; current behaviour is pinned by `pkg/bitmap/rle_test.go` so the
  fix can land with a deliberate test update rather than as a stealth
  visual-difference report.

## Test coverage

- Unit-test `parseServerCertificate` against a corpus of real-world server
  certs (proprietary + X.509 chain), including the Microsoft "rdpRsa" OID
  variant.
- Unit-test `deriveSessionKeys` and `deriveLicenseKeys` against vectors
  scraped from a FreeRDP debug build.

## Done in this push

- **Modern-server capture fix.** CS_CORE was advertising an incoherent
  highColorDepth / supportedColorDepths / earlyCapabilityFlags /
  connectionType set. Server 2012R2+ RST the connection right after MCS
  Connect Initial rather than replying with a Connect Response, so every
  post-2012 host produced "connection reset" (0/100 modern). Aligning the
  fields with a modern mstsc (24bpp preferred, all depths supported,
  ERRINFO+VALID_CONNECTION_TYPE, CONNECTION_TYPE_LAN) took a 100-target
  modern sample from 0 -> 87 captured, and the full reachable non-NLA set
  to ~86% (was 3%). Verified against live Win10/Server-2019 logon screens.
- **Reactivation handler.** The capture loop now handles the
  Deactivate-All -> new Demand Active sequence ([MS-RDPBCGR] §1.3.1.3) that
  modern hosts run mid-session, re-Confirming Active and re-finalizing on
  the new share instead of stalling.
- Smart `-anonymous` fallback (reconnect without HYBRID on CredSSP failure).
- `pkg/rdp/client.go` split into `connect.go` / `secure.go` / `read.go`.
- NTLM extracted into `pkg/rdp/ntlm.go`; `credssp.go` keeps SPNEGO/TSRequest.
- `pkg/rdp/per/` subpackage with PER primitives + round-trip unit tests.
- `pkg/bitmap/rle_test.go` golden vectors covering 8/16/24/32 bpp opcode families.
- CLI `-output-format text|json` for jq-friendly per-target results.

## Tooling

- `Makefile` or `mage` target for cross-compilation and `goreleaser` for
  signed release artefacts.
- GitHub Actions: `go vet`, `go test -race`, `go build` matrix on Linux /
  macOS / Windows.

## Out of scope (intentionally)

- Interactive sessions (mouse / keyboard input loops).
- File-system or printer redirection.
- A reverse mode (RDP server in pure Go).
