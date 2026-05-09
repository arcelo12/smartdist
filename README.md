# SmartDist

> **SmartDNS-style configuration for DnsDist** — Replicate SmartDNS features (IP aliasing, domain-set exclusions, wildcard CNAME) in DnsDist 2.x with a simple Lua plugin, packaged with Docker.

## ✨ Features

- **SmartDNS-like syntax** — Familiar `ip-set`, `domain-set`, `cname`, and `ip-rules` functions
- **IP Alias (ip-rules)** — Rewrite DNS A/AAAA responses matching a CDN's IP range to your preferred edge IP
- **Multiple target IPs** — Round-robin support for multiple alias targets
- **IPv4 & IPv6** — Automatic detection and handling of both A and AAAA records
- **Domain exclusion** — Skip aliasing for specific domains via domain-set
- **Wildcard CNAME** — Spoof CNAME for wildcard domain patterns
- **Plugin architecture** — Clean separation between plugin logic and user configuration
- **Cloudflare Node Checker** — Built-in Go TUI tool to verify which CF edge node you're hitting

## 📁 Project Structure

```
SmartDist/
├── dnsdist.conf            # Main config (user rules go here)
├── smartdns_plugin.lua     # Plugin: SmartDNS compatibility layer
├── docker-compose.yml      # Docker deployment
├── cdn-ips/                # IP & domain lists
│   └── cloudflare/
│       ├── ipv4.txt        # Cloudflare IPv4 ranges
│       ├── ipv6.txt        # Cloudflare IPv6 ranges
│       └── exclude.txt     # Domains to exclude from aliasing
├── cf-node-test.sh         # Bash CF node checker (lightweight)
└── cf-checker/             # Go TUI CF node checker (parallel)
    └── main.go
```

## 🚀 Quick Start

### 1. Clone & Configure

```bash
git clone https://github.com/arcelo12/smartdist.git
cd smartdist
```

Edit `dnsdist.conf` to set your upstream DNS and alias rules:

```lua
-- Bind port
setLocal('0.0.0.0:5300')
setACL({"0.0.0.0/0", "::/0"})

-- Load plugin
dofile("/etc/dnsdist/smartdns_plugin.lua")

-- Define IP sets & domain sets
smartdns_ip_set("cloudflare-ipv4", "/etc/smartdns/cdn-ips/cloudflare/ipv4.txt")
smartdns_ip_set("cloudflare-ipv6", "/etc/smartdns/cdn-ips/cloudflare/ipv6.txt")
smartdns_domain_set("cf-exclude", "/etc/smartdns/cdn-ips/cloudflare/exclude.txt")

-- CNAME mapping (wildcard)
smartdns_cname("-.api.x.com", "api.x.com.cdn.cloudflare.net.")

-- IP alias rules (multiple targets = round-robin)
smartdns_ip_rules_alias("cloudflare-ipv4", {"172.64.52.159", "172.64.87.224"}, "cf-exclude")
smartdns_ip_rules_alias("cloudflare-ipv6", {"2606:4700:0:970d:906d:a6e9:605b:dfd"}, "cf-exclude")

-- Upstream resolver
newServer("8.8.8.8")
```

### 2. Deploy with Docker

```bash
docker compose up -d
```

### 3. Test

```bash
nslookup cloudflare.com <your-server-ip>
```

## 🔌 Plugin API Reference

### `smartdns_ip_set(name, filepath)`

Load an IP range list into a named NetmaskGroup.

```lua
smartdns_ip_set("cloudflare-ipv4", "/etc/smartdns/cdn-ips/cloudflare/ipv4.txt")
```

**File format:** One CIDR per line (e.g. `173.245.48.0/20`). Lines starting with `#` are ignored.

### `smartdns_domain_set(name, filepath)`

Load a domain list into a named SuffixMatchNode.

```lua
smartdns_domain_set("cf-exclude", "/etc/smartdns/cdn-ips/cloudflare/exclude.txt")
```

**File format:** One domain per line. Wildcard prefix `*.` is auto-stripped.

### `smartdns_cname(pattern, target)`

Spoof CNAME for matching domains (supports SmartDNS `-.` and `.` wildcard prefixes).

```lua
smartdns_cname("-.api.x.com", "api.x.com.cdn.cloudflare.net.")
```

### `smartdns_ip_rules_alias(ip_set_name, target_ips, exclude_domain_set)`

Rewrite DNS responses: if any A/AAAA record matches the ip-set, replace all matching records with target IP(s).

```lua
-- Single target
smartdns_ip_rules_alias("cloudflare-ipv4", "172.64.87.224", "cf-exclude")

-- Multiple targets (round-robin)
smartdns_ip_rules_alias("cloudflare-ipv4", {"172.64.52.159", "172.64.87.224"}, "cf-exclude")

-- IPv6 (auto-detected from target format)
smartdns_ip_rules_alias("cloudflare-ipv6", {"2606:4700:0:970d:906d:a6e9:605b:dfd"}, "cf-exclude")
```

## 🔍 Cloudflare Node Checker

### Bash (lightweight)

```bash
# Test builtin 36 domains
bash cf-node-test.sh --dns <dns-server-ip>

# Test custom domains
bash cf-node-test.sh --dns <dns-server-ip> cloudflare.com mysite.com

# Builtin + custom
bash cf-node-test.sh --dns <dns-server-ip> --all mysite.com
```

### Go TUI (parallel, real-time)

```bash
# Build
cd cf-checker && go build -o cf-checker-bin .

# Run
./cf-checker-bin --dns <dns-server-ip>
./cf-checker-bin --dns <dns-server-ip> --all mysite.com
```

Features: 10 concurrent goroutines, IPv6 priority, real-time spinner, scrollable table, progress bar, CF node summary.

## 📋 Requirements

- **DnsDist 2.x** (tested on 2.0.5)
- **Docker** & **Docker Compose**
- **Go 1.21+** (only for building cf-checker)

## 📜 License

MIT
