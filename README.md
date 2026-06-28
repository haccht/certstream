# ctlog-go

Small Certificate Transparency log tailer written in Go.

It polls RFC 6962 CT logs, extracts domain names from X.509 certificates and
precertificates, streams new entries, and lists public logs.

## Build

Build a local binary:

```sh
go build -o ctlog-go .
```

Move it somewhere on your `PATH` if you want to run it from any directory:

```sh
install -m 0755 ctlog-go /usr/local/bin/ctlog-go
```

## Usage

```sh
ctlog-go list
ctlog-go stream https://ct.cloudflare.com/logs/nimbus2026/ct/v1
```

Useful options:

```sh
ctlog-go stream --debug https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1
ctlog-go stream --start 2800000000 https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1
ctlog-go stream --batch-size 10 https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1
ctlog-go stream "$(ctlog-go list | head -n1)"
```

## Options

`ctlog-go list` prints Chrome's CT log list as stream-ready URLs, one URL per
line.

`ctlog-go stream <URL>` streams one CT log. Options are long-form only:

- `--start`: Entry index to start from. The default `-1` starts near the current
  tree tail.
- `--batch-size`: Number of entries requested per poll. Default is `3`.
- `--debug`: Print retry and parse errors to stderr.

## Example CT Logs

```sh
ctlog-go stream https://ct.cloudflare.com/logs/nimbus2026/ct/v1
ctlog-go stream https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1
ctlog-go stream https://ct.googleapis.com/logs/eu1/xenon2026h1/ct/v1
ctlog-go stream https://wyvern.ct.digicert.com/2026h1/ct/v1
ctlog-go stream https://sphinx.ct.digicert.com/2026h1/ct/v1
ctlog-go stream https://mammoth2026h1.ct.sectigo.com/ct/v1
```

Google's published log list is available at:

```text
https://www.gstatic.com/ct/log_list/v3/log_list.json
```
