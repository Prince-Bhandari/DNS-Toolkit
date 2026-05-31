# DNS Toolkit
A comprehensive Python library and CLI for DNS analysis, including lookups, WHOIS, propagation checking, DNSSEC validation, blacklist checking, and more.
## Features
- **DNS Lookup**: Query any DNS record type (A, AAAA, MX, TXT, etc.)
- **All Records**: Fetch all DNS records for a domain at once
- **Reverse Lookup**: PTR record lookups for IP addresses
- **Domain Validation**: Validate domain format, check registration, IDN support
- **WHOIS Lookup**: Registration info, expiry dates, registrant details
- **Propagation Check**: Verify DNS propagation across global servers
- **Response Time**: Benchmark DNS servers, find the fastest
- **DNSSEC**: Check and validate DNSSEC configuration
- **Blacklist Check**: Check IPs against DNS blacklists (DNSBL)
- **Subdomain Enumeration**: Discover subdomains via wordlist, zone transfer, or CT logs
- **Email Config**: Verify MX, SPF, DKIM, and DMARC records
- **Caching & History**: Cache results and track DNS history
## Installation
```bash
pip install -e .

or 

pip install -r requirements.txt



## CLI Usage
# Basic lookup
dns-toolkit lookup example.com
dns-toolkit lookup example.com -t MX
dns-toolkit lookup example.com --all
# Reverse lookup
dns-toolkit reverse 8.8.8.8
# Validate domain
dns-toolkit validate example.com
# WHOIS lookup
dns-toolkit whois example.com
# Check propagation
dns-toolkit propagation example.com
# Benchmark DNS servers
dns-toolkit benchmark example.com
# Check DNSSEC
dns-toolkit dnssec example.com
# Check blacklists
dns-toolkit blacklist 192.0.2.1
# Find subdomains
dns-toolkit subdomains example.com
dns-toolkit subdomains example.com --comprehensive
# Check email config
dns-toolkit email example.com
# Full analysis
dns-toolkit full example.com
# JSON output (all commands)
dns-toolkit lookup example.com --json