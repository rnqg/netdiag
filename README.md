<h1 align="center"><img src="docs/netdiag.svg" width="34" alt="" /> netdiag</h1>

<p align="center"><strong>Find where a network connection fails.</strong><br />
DNS, HTTPS, and latency checks for Windows, macOS, and Linux.</p>

<p align="center">
  <a href="https://github.com/rnqg/netdiag/actions/workflows/ci.yml"><img src="https://github.com/rnqg/netdiag/actions/workflows/ci.yml/badge.svg?branch=main" alt="Tests and builds" /></a>
</p>

<p align="center">
  <a href="https://github.com/rnqg/netdiag/releases/latest">Download</a> · <a href="#install">Install</a> · <a href="#usage">Usage</a> · <a href="docs/guide.md">User guide</a> · <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <img src="docs/demo.svg" width="680" alt="Example run: example.org replies over HTTPS and times out over ICMP. The local gateway replies to all three probes with a median RTT of 2.38 ms." />
</p>

In this run, the site answered over HTTPS even though it didn't answer a ping.
netdiag reports those results separately and measures RTT to the local gateway.
Basic checks need no account or measurement server. Terminal output is in Russian.

## Install

Download the archive for your system, then extract it. Go is only needed to build from source.

| Platform | x86-64 | ARM64 |
| --- | --- | --- |
| Windows | [.zip](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-windows-amd64.zip) | [.zip](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-windows-arm64.zip) |
| macOS | [Intel](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-macos-amd64.tar.gz) | [Apple Silicon](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-macos-arm64.tar.gz) |
| Linux | [.tar.gz](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-linux-amd64.tar.gz) | [.tar.gz](https://github.com/rnqg/netdiag/releases/latest/download/netdiag-linux-arm64.tar.gz) |

The archive contains `netdiag` and `netdiag-node`. Open a terminal in the extracted folder and run `./netdiag --help`. In Windows PowerShell, run `.\netdiag.exe --help`.

[Latest release](https://github.com/rnqg/netdiag/releases/latest) · [SHA-256 checksums](https://github.com/rnqg/netdiag/releases/latest/download/SHA256SUMS)

<details>
<summary>Build from source</summary>

Requires Go 1.27.4 or later.

```sh
git clone https://github.com/rnqg/netdiag.git
cd netdiag
go build -o netdiag ./cmd/netdiag
```

On Windows, build with `go build -o netdiag.exe ./cmd/netdiag` and run `.\netdiag.exe` in PowerShell.

</details>

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
