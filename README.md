# cf_speedtest

## A simple command-line internet speed test tool. Powered by https://speed.cloudflare.com 


## Installation:
```bash
$ cargo install cf_speedtest
```

## Usage:
	$ cf_speedtest


## FAQ
- Why did you make this?
	- See below
- Why would I want to use this?
	- You don't have to use this, but it can reach much faster speeds than browser speedtests

### TODO:
- Adaptively increase thread count if speed keeps increasing
- Add ability to specify thread count (upload and download)
- Support for proxies (HTTP/SOCKS5) with and without authentication
- Output results to csv?
- Reduce CPU usage by not decrypting TLS?

### Disclaimers:
- This tool works entirely over HTTP(S), which has some overhead