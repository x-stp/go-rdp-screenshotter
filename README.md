# RDP Screenshotter (Go)

A lightweight RDP (Remote Desktop Protocol) client written in Go. 
Capture screenshots from RDP servers without requiring full auth.

## Features

- Minimal RDP protocol implementation focused on screenshot capture
- Support for multiple targets from a file
- Configurable connection timeout
- No external dependencies (pure Go implementation)

## LT wishlist
- Support for CredSSP/NLA authentication
 - this needs to be worked out in `pkg/rdp/security.go`
    - FreeRDP/FreeRDP, rdesktop, citronneur/rdp-rs etc.
     - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685
      -https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/9664994d-0784-4659-b85b-83b8d54c2336
- Support for RDP compression - spec:
      -https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a02c7496-2eb4-45d4-b8d1-99e98e61fe21 [rfc 2118]
- Add proper bitmap to PNG conversion 
- Implement RDP 8+ features
- Add concurrency
- Unit tests

## Installation

```bash
go install github.com/x-stp/rdp-screenshotter-go@latest
```

Or build from source:

```bash
git clone https://x-stp.com/yourusername/rdp-screenshotter-go
cd rdp-screenshotter-go
go build -o rdp-screenshotter ./cmd/main.go
```

## Usage

```ksh
./rdp-screenshotter -targets target.txt
```

### Command Line Options

```
-targets string
    File containing RDP targets (one per line) (default "target.txt")
-timeout duration
    Connection timeout (default 10s)
-username string
    Username for RDP cookie (optional)
-output string
    Output directory for screenshots (default "screenshots")
```

### Example

```bash
# Capture screenshots with custom timeout and output directory
./rdp-screenshotter -targets servers.txt -timeout 30s -output ./captures

# With username cookie
./rdp-screenshotter -targets target.txt -username admin
```

## Protocol Support

The implementation supports:

- TPKT (RFC 1006) transport
- X.224 connection establishment
- Basic MCS (T.125) channel management
- RDP security negotiation
- Basic RDP connection sequence

### Security Modes

The client attempts to negotiate the following security modes:
- Standard RDP Security
- TLS/SSL Security
- Network Level Authentication (NLA) - detection only

**Note**: Currently, only standard RDP security is fully implemented. 

Servers requiring TLS or NLA will be detected but connection will fail, cert chain not logged yet.

## Limitations

- Only captures the initial screen (no interaction / mouse)
- Limited to servers allowing standard RDP security
- No support for CredSSP/NLA authentication (see LT wishlist)
- Basic bitmap format support only
- No RDP compression support


### Project Structure

```ksh
|----------------------------------------------------------|
|── pkg/                                                   |
|   └── rdp/                                               |
|       ├── client.go        # RDP client implementation   |
|       ├── constants.go     # Protocol constants          |
|       ├── tpkt.go         # TPKT layer                   |
|       ├── x224.go         # X.224 layer                  |
│       ├── mcs.go          # MCS layer                    |
│       ├── security.go     # Security functions           |
│       ├── pdu.go          # PDU builders/parsers         |
│       ├── bitmap.go       # Bitmap handling              |
│       └── client_test.go  # Unit tests                   |
|----------------------------------------------------------|
```

## DISCLAIMER

This tool is designed for authorized security testing and system administration only. 

**Important**:
- Only use on systems you own or have explicit permission to test
- The tool may trigger security alerts on target systems
- RDP sessions on Win usually go to event viewer. 
- Modern RDP servers may require NLA which this tool doesn't yet support

### TODO

- [ ] Add decent TLSv1.0-TLS1.2 support
- [ ] Support RDP compression
- [ ] Add proper bitmap to PNG conversion
- [ ] Support 8b bitmap as most RDP services are cheap
- [ ] Implement RDP 8+ features
- [ ] CredSSP/NLA authentication
- [ ] Add concurrent target processing


## Enjoy obscure protocol specs 

- FreeRDP project for protocol insights.
- ITU-T X.680;
- RFC 1155;
- ITU-T X.690; 
- RFC 6025;
- Microsoft RDP documentation (MS-RDPBCGR);

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0) - see the LICENSE file for details.

The AGPL license ensures that any modifications to this software, including when used as a network service, must be made available under the same license terms.
