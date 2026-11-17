# netdiag user guide

[README](../README.md) · [Русский](guide.ru.md)

## Quick start

You'll need Go **1.27.4** or later. On macOS or Linux:

```sh
git clone https://github.com/rnqg/netdiag.git
cd netdiag
go build -o netdiag ./cmd/netdiag
./netdiag check --mode direct --profile quick
```

<details>
<summary>Build and run in Windows PowerShell</summary>

```powershell
git clone https://github.com/rnqg/netdiag.git
cd netdiag
go build -o netdiag.exe ./cmd/netdiag
.\netdiag.exe check --mode direct --profile quick
```

Use `.\netdiag.exe` in place of `./netdiag` in the other examples.

</details>

A basic check needs no account or measurement node. Choose `direct` when disconnected from the VPN and `vpn` when connected. The `direct` list includes Russian sites such as Yandex and VK. The `vpn` list includes YouTube, Discord, and GitHub. Switch the connection in your VPN client. Terminal output is currently in Russian.

| Task | Command |
| --- | --- |
| Check one site | `./netdiag check --mode direct --only-target --target example.org` |
| Measure RTT, jitter, and loss | `./netdiag quality --mode direct --duration 60s` |
| Save a report | `./netdiag check --mode direct --output direct.json` |
| See all commands and flags | `./netdiag --help` |

`check` uses the `deep` profile by default (up to 180 seconds). `quick` is capped at 60 seconds. Repeat `--target` to add addresses. Use `--only-target` to skip the built-in list and `--trace` to add a traceroute.

## What netdiag checks

- **Network and Wi-Fi.** Interfaces, gateway, MTU, available Wi-Fi radio metrics, and connection changes.
- **DNS and reachability.** A/AAAA records, DNS over UDP, TCP, DoH, and DoT, plus IPv4/IPv6, TCP, TLS 1.2/1.3, HTTP/1.1, HTTP/2, and HTTP/3 when advertised via Alt-Svc.
- **Connection quality.** ICMP RTT, loss, and jitter. A measurement node adds UDP probes and a test for the largest payload observed to pass.

Probes follow OS routing. Browser results can differ when a proxy, PAC file, or extension is involved. A timeout shows which stage received no reply. Compare other protocols and targets to narrow down the cause.

## Speed and bufferbloat

With your own node, you can measure download, upload, and both at once. For each phase, netdiag compares p95 RTT before, during, and after the load.

Set `NETDIAG_NODE_TOKEN` to your node's token on the client, then run:

```sh
./netdiag speed --mode direct --node https://node.example.org:8443 --max-mib 1024
```

For reachability, RTT, and load measurements in one report, use `check --full`:

```sh
./netdiag check --mode direct --full --trace \
  --node https://node.example.org:8443 --output full.json
```

`--max-mib` caps test payloads. Protocol overhead is additional. If the test runs out of data budget, the report is partial. To raise the budget, increase the limit on both the client and the node.

<details>
<summary>How RTT, loss, and bufferbloat are calculated</summary>

- Jitter is the mean absolute RTT difference between consecutive successful probes, skipping pairs with a missing probe in between. The report includes p99 once there are at least 100 successful probes.
- A probe counts as lost if its reply misses the deadline. Late replies and send errors are counted separately.
- Bufferbloat is the change in p95 UDP RTT to the same node. The first 5 seconds of each idle and loaded measurement are excluded. The test needs at least 50 replies in each compared interval, sustained traffic, and a recovery check.
- If p95 rises by at least 20 ms and then recovers, netdiag can compare normal load with a cap at 70% of observed throughput, followed by another normal run. This trial leaves router and OS settings as they were.

</details>

### Speed without a node

```sh
./netdiag speed --mode direct --accept-mlab-policy --max-mib 256
```

> [!IMPORTANT]
> M-Lab publishes test results alongside your public IP address. This mode measures throughput with one stream in each direction. Bufferbloat requires your own node. [M-Lab privacy policy](https://www.measurementlab.net/privacy/) · [Acceptable use policy](https://www.measurementlab.net/aup/)

### Run your own measurement node

Build `netdiag-node` on the server and start it with a TLS certificate your client trusts:

```sh
go build -o netdiag-node ./cmd/netdiag-node
export NETDIAG_NODE_TOKEN="$(openssl rand -hex 32)"
./netdiag-node --listen :8443 --udp :4444 \
  --cert /etc/netdiag/fullchain.pem --key /etc/netdiag/privkey.pem
```

Allow **8443/TCP** for HTTPS, **8443/UDP** for HTTP/3, and **4444/UDP** for echo probes. HTTPS and UDP must reach the same node with the client address preserved. Set the same `NETDIAG_NODE_TOKEN` on the client. In PowerShell, use `$env:NETDIAG_NODE_TOKEN`.

<details>
<summary>Run the node in Docker</summary>

```sh
docker build -t netdiag-node .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env NETDIAG_NODE_TOKEN -p 8443:8443/tcp -p 8443:8443/udp -p 4444:4444/udp \
  -v /etc/netdiag:/certs:ro netdiag-node \
  --cert /certs/fullchain.pem --key /certs/privkey.pem
```

The container runs as UID 65532 and needs read access to the certificate and key.

</details>

## Reports

Save a report without the VPN, then connect the VPN and repeat checks against the same sites:

```sh
./netdiag check --mode direct --output direct.json
./netdiag compare --baseline direct.json --mode vpn --output comparison.json
./netdiag report --input comparison.json --verbose
```

`compare` reuses the targets and profile from the baseline. For a `check --full` report, it repeats the reachability checks. `--format json` writes JSON to stdout. `--output` saves a file and refuses to overwrite an existing one.

netdiag does not upload reports automatically. Review domains, target addresses, and your node address before sharing. Reports omit the SSID, MAC address, and node token.

**Exit codes:** `0` for a check with no errors, `1` when a check found an error, `2` when the command couldn't run or save its result, and `3` for a partial measurement.

## DNS fixes

```sh
./netdiag fix --input direct.json
./netdiag fix --input direct.json --apply
./netdiag fix --flush-cache --input direct.json --apply
```

The first command prints manual instructions. Applying a fix requires an interactive confirmation and administrator rights. A DNS change needs a recent report with a working alternative confirmed over UDP. Use the manual instructions if a VPN, proxy, or network management policy is detected. On Linux, changing DNS requires NetworkManager.

netdiag saves the original settings, checks the result, and rolls the change back if it can't verify the fix or obtain confirmation. If rollback can't be confirmed, pass the printed path to `./netdiag fix --recover <path>`. Automatic rollback after a power loss is not guaranteed.

With `--input`, `--flush-cache` checks the affected site before and after the flush. To pick a site manually, use `--target example.org` in place of `--input`.

## Development

```sh
go test -race ./...
go vet ./...
```

[Measurement node protocol (Russian)](../PROTOCOL.md) · [Third-party licenses](../THIRD_PARTY_NOTICES.md)
