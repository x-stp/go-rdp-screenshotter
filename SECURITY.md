# security policy

Vulnerabilities in rdp-screenshotter should be reported privately.

## reporting a vulnerability

If you believe you've found a security issue in rdp-screenshotter:

- Email **security@vanderstap.info**
- Include **"SECURITY"** and **"rdp-screenshotter"** in the subject line
- Provide:
  - A description of the issue
  - Steps to reproduce
  - Any proof-of-concept code or logs
  - The version(s) of rdp-screenshotter you tested against

Do not open a public GitHub issue for security vulnerabilities.

## what to expect

1. Acknowledgement within 5 working days.
2. Investigation: confirm the problem, determine affected versions, audit related code.
3. Fix and release as quickly as reasonably possible.
4. Optional credit in changelog or release notes if you wish.

## responsible disclosure

Give us reasonable time to investigate and fix before public disclosure. Coordinated disclosure protects everyone who uses rdp-screenshotter.

## scope note

rdp-screenshotter is an offensive-security / research tool for authorized RDP reconnaissance. Reports about the tool *being used* against systems you don't own are out of scope — that's a matter for the operator, not this project. Reports about defects in the tool (memory safety, credential handling, TLS/CredSSP verification gaps) are in scope.
