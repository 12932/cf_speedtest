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
	- You don't have to use this, but it can achieve much faster speeds than browser speedtests

### TODO:
- Use std::async or tokio instead of threads
- Support for proxies (HTTP/SOCKS5) with and without authentication
- Output results to csv?
- Show a graph
- Show speed percentiles, and allow user to specify their own

### Disclaimers:
- This tool works entirely over HTTP(S), which has some overhead