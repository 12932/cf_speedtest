# cf_speedtest

## What is this?
cf_speedtest is an unofficial, cross-platform, command-line internet speed test tool, powered by https://speed.cloudflare.com. cf_speedtest leverages Cloudflare's own Speedtest API, it can achieve much higher speeds than other tools. Here is an example of  cf_speedtest running on an [AWS m5zn.6xlarge instance](https://aws.amazon.com/blogs/aws/new-ec2-m5zn-instances-fastest-intel-xeon-scalable-cpu-in-the-cloud/) (advertised as 50Gbit capable):

[![asciicast](https://asciinema.org/a/ujPEsr7KuGkNtcF7MGzemRO9z.svg)](https://asciinema.org/a/ujPEsr7KuGkNtcF7MGzemRO9z)

## Installation:
```bash
$ cargo install cf_speedtest
```

## Usage:
	$ cf_speedtest


### TODO:
- Use rustls instead of ureq for download tests, to avoid TLS decryption cost
- Support for proxies (HTTP/SOCKS5)
- Option to output results to CSV file

### Disclaimers:
- This tool works entirely over HTTPS, which has some overhead
- This tool is completely unofficial, Cloudflare can block this tool at any time if they wanted to (I suspect they won't, because they chill like that)