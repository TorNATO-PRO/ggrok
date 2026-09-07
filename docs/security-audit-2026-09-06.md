# Security audit — 2026-09-06

Reviewed the CLI credential and output paths, CA issuance and revocation,
TLS configuration, relay admission and stream ownership, and protocol framing
and authentication. This is a source review with regression tests, not a
claim that every possible vulnerability has been excluded.

## Findings fixed

| Finding | Impact | Change |
| --- | --- | --- |
| Empty session-key file silently fell back to an environment key or a generated key | A publisher could start with a different session identity than explicitly configured | Reject empty and whitespace-only secret files before selecting another source |
| CRL export truncated the destination before writing | A concurrent reload could install an empty or partial revocation set; symlinks could redirect the write | Write a private temporary file, sync and close it, then replace the destination; sort serials for stable output |
| Peer-controlled text was printed as terminal instructions | Certificate names or relay responses could inject ANSI sequences, extra rows, or bidirectional control characters into operator output | Escape untrusted fields in admin/CA listings, mutation output, CLI errors, and reconnect diagnostics |

CRL replacement uses a same-directory rename, which is atomic on Unix.
Non-Unix platforms do not have the same guarantee from Go's `os.Rename`.
The destination directory must remain under the operator's control. Copying
an exported CRL to another machine also needs a complete-file replacement
if that machine can reload during the copy.

## Cleanup

- Give the CA key a concrete ML-DSA type and remove the unchecked assertion.
- Remove unused stream socket references; connection eviction stays in the transport tracker.
- Replace outdated CLI comments that incorrectly described relay payload confidentiality.

## Validation

- `go test -race ./...`: passed, including the new regressions and existing
  publisher-claim, replay, tampering, certificate-binding, and live-revocation tests.
- `golangci-lint run ./...`: zero issues.
- `go vet ./...`, formatting, and diff whitespace checks: passed.
- `go mod verify` and `go mod tidy -diff`: passed with no module changes.
- Linux and Windows amd64 cross-compilation: passed. Runtime tests ran on macOS.

## Vulnerability database scan

After approval, `govulncheck v1.6.0 -show verbose ./...` completed against
Go 1.27.0 and `golang.org/x/crypto v0.56.0`. The installed scanner had been
built with Go 1.26, so the same version was rebuilt using Go 1.27 from cached
source, with module downloads disabled.

The scan reported **zero vulnerabilities in called symbols or imported packages**.
It reported one module-level advisory,
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), for the unmaintained
`golang.org/x/crypto/openpgp` package. GGrok does not import that package, and
the advisory lists no fixed version. No dependency update was needed for this
finding. This result reflects the database at the time of the scan.
