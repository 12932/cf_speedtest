# cf_speedtest

## What is this?
cf_speedtest is an unofficial, cross-platform, command-line internet speed test tool, powered by https://speed.cloudflare.com. cf_speedtest leverages Cloudflare's own Speedtest API, it can achieve much higher speeds than other tools. Here is me running cf_speedtest on an AWS m5zn.metal instance:


## Installation:
```bash
$ cargo install cf_speedtest
```

## Usage:
	$ cf_speedtest


### TODO:
- Use rustls instead of ureq for download tests, to avoid TLS decryption cost
- Support for proxies (HTTP/SOCKS5) with and without authentication
- Output results to csv

### Disclaimers:
- This tool works entirely over HTTPS, which has some overhead
- This tool is completely unofficial, Cloudflare can block this tool at any time if they wanted to (I suspect they won't, because they chill like that)