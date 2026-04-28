# cf_speedtest

## What is this?
cf_speedtest is an unofficial, cross-platform, command-line internet speed test tool, powered by https://speed.cloudflare.com. By leveraging Cloudflare's Speedtest API and reading raw encrypted bytes from the socket (bypassing TLS decryption overhead), cf_speedtest can achieve much higher speeds than other tools.

Each test reports:
- Download and upload speeds (median, average, 90th percentile)
- HTTP latency and jitter
- Your location and the Cloudflare server location (IATA code, city, country)

Here is an example of cf_speedtest running on an [AWS m5zn.6xlarge instance](https://aws.amazon.com/blogs/aws/new-ec2-m5zn-instances-fastest-intel-xeon-scalable-cpu-in-the-cloud/) (advertised as 50Gbit capable):

[![asciicast](https://asciinema.org/a/ujPEsr7KuGkNtcF7MGzemRO9z.svg)](https://asciinema.org/a/ujPEsr7KuGkNtcF7MGzemRO9z)

## Installation
```bash
$ cargo install cf_speedtest
```

## Usage
```
$ cf_speedtest
```

### Options
| Flag | Description | Default |
|------|-------------|---------|
| `--download-threads` | Number of download threads | 8 |
| `--upload-threads` | Number of upload threads | 8 |
| `-d`, `--download-only` | Only run the download test | |
| `-u`, `--upload-only` | Only run the upload test | |
| `--bytes-to-download` | Bytes per download request | 50MB |
| `--bytes-to-upload` | Bytes per upload request | 50MB |
| `--test-duration-seconds` | Duration of each upload/download test | 12 |
| `--format` | Output format: `json` or `csv` | human-readable |
| `--no-header` | Omit the header row from CSV output | |

### Structured output
```bash
# JSON output
$ cf_speedtest --format json

# CSV output (first run with header, then append without)
$ cf_speedtest --format csv > results.csv
$ cf_speedtest --format csv --no-header >> results.csv
```

Output includes: version, timestamp, server IATA/city/country, user country, latency (ms), jitter (ms), and download/upload speeds in both bytes/sec and Mbit/s (median, average, 90th percentile).

### Disclaimers
- This tool is completely unofficial, Cloudflare can block this tool at any time if they wanted to (I suspect they won't, because they chill like that)