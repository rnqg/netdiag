<h1 align="center"><img src="docs/netdiag.svg" width="34" alt="" /> netdiag</h1>

<p align="center"><strong>Find where a network connection fails.</strong><br />
DNS, HTTPS, and latency checks for Windows, macOS, and Linux.</p>

<p align="center">
  <a href="https://github.com/rnqg/netdiag/actions/workflows/ci.yml"><img src="https://github.com/rnqg/netdiag/actions/workflows/ci.yml/badge.svg?branch=main" alt="Tests and builds" /></a>
</p>

<p align="center">
  <a href="#install">Install</a> · <a href="#usage">Usage</a> · <a href="docs/guide.md">User guide</a> · <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <img src="docs/demo.svg" width="680" alt="Example run: example.org replies over HTTPS and times out over ICMP. The local gateway replies to all three probes with a median RTT of 2.38 ms." />
</p>

In this run, the site answered over HTTPS even though it didn't answer a ping.
netdiag reports those results separately and measures RTT to the local gateway.
Basic checks need no account or measurement server. Terminal output is in Russian.

## Install

Build from source with Go 1.27.4 or later. Supported architectures are amd64 and arm64.

```sh
git clone https://github.com/rnqg/netdiag.git
cd netdiag
go build -o netdiag ./cmd/netdiag
```

On Windows, build with `go build -o netdiag.exe ./cmd/netdiag` and run `.\netdiag.exe` in PowerShell.

## Usage

**Check one site.** See whether DNS, TCP, TLS, and HTTP respond.

```sh
./netdiag check --mode direct --profile quick \
  --only-target --target example.org
```

**Measure connection quality.** See RTT percentiles, jitter, and unanswered probes.

```sh
./netdiag quality --mode direct --duration 60s
```

**Compare before and after connecting to a VPN.** Run the first command with the VPN off. Turn it on before running the second.

```sh
./netdiag check --mode direct --output direct.json
./netdiag compare --baseline direct.json --mode vpn
```

**Measure speed and bufferbloat.** A [measurement node](docs/guide.md#run-your-own-measurement-node) provides throughput and p95 RTT before, during, and after load. Set its token in `NETDIAG_NODE_TOKEN` before running:

```sh
./netdiag speed --mode direct --node https://node.example.org:8443
```

## Documentation

- [Commands, reports, and DNS fixes](docs/guide.md)
- [Measurement node setup and Docker](docs/guide.md#run-your-own-measurement-node)
- [Measurement node protocol](PROTOCOL.md) (Russian)

[Apache 2.0](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md)
