# certstream

Small Certificate Transparency log tailer written in Go.

It polls an RFC 6962 CT log, extracts domain names from X.509 certificates and
precertificates, and prints one line per log entry.

## Build

Build a local binary:

```sh
go build -o certstream .
```

Move it somewhere on your `PATH` if you want to run it from any directory:

```sh
install -m 0755 certstream /usr/local/bin/certstream
```

## Usage

```sh
certstream logs
certstream watch https://ct.cloudflare.com/logs/nimbus2026/ct/v1
```

Useful options:

```sh
certstream watch -debug https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1
certstream watch -start 2800000000 https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1
certstream watch -batch-size 10 https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1
certstream watch "$(certstream logs | head -n1)"
```

## Options

`certstream logs` prints Chrome's CT log list as watch-ready URLs, one URL per
line.

`certstream watch <URL>` streams one CT log. Its options are:

- `-start`: Entry index to start from. The default `-1` starts near the current
  tree tail.
- `-batch-size`: Number of entries requested per poll. Default is `3`.
- `-debug`: Print retry and parse errors to stderr.

## Example CT Logs

```sh
certstream watch https://ct.cloudflare.com/logs/nimbus2026/ct/v1
certstream watch https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1
certstream watch https://ct.googleapis.com/logs/eu1/xenon2026h1/ct/v1
certstream watch https://wyvern.ct.digicert.com/2026h1/ct/v1
certstream watch https://sphinx.ct.digicert.com/2026h1/ct/v1
certstream watch https://mammoth2026h1.ct.sectigo.com/ct/v1
```

Google's published log list is available at:

```text
https://www.gstatic.com/ct/log_list/v3/log_list.json
```
