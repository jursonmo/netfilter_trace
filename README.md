# nftracepath

`nftracepath` traces one IPv4 TCP/UDP five-tuple through Linux netfilter on a local or SSH target.

It installs temporary, exact-match trace/probe rules, observes netfilter trace or kernel log output for a bounded time, then removes the temporary rules.

## Build

```sh
go build ./cmd/nftracepath
```

On machines with tight temporary disk space, keep Go build files inside the repo:

```sh
mkdir -p .gotmp .gocache
GOTMPDIR=$PWD/.gotmp GOCACHE=$PWD/.gocache go build ./cmd/nftracepath
```

## Basic usage

Interactive:

```sh
sudo ./nftracepath run
```

交互式运行会逐项提示协议、地址、可选端口、入接口、模式、后端 `auto|nft|iptables` 和目标信息。输入完成后会打印一行等价的完整命令，方便复制复用，例如：

```sh
./nftracepath run --proto tcp --src 192.0.2.10 --sport 12345 --dst 198.51.100.20 --dport 443 --mode listen --backend nft --target local --timeout 30s --max-events 200 --trace-limit 10/second --trace-limit-burst 20 --allow-broad-match=false --debug=false --json=false --sudo=false
```

Non-interactive:

```sh
sudo ./nftracepath run \
  --proto tcp \
  --src 192.0.2.10 --sport 12345 \
  --dst 198.51.100.20 --dport 443 \
  --in-iface eth0 \
  --mode listen \
  --timeout 30s
```

Source and destination ports are optional. When `--sport` or `--dport` is omitted, the temporary nftables/iptables rules simply do not include that port match:

```sh
sudo ./nftracepath run \
  --proto tcp \
  --src 192.0.2.10 \
  --dst 198.51.100.20 \
  --mode listen \
  --allow-broad-match
```

When both ports are omitted the match can be broad, so the tool rejects it unless `--allow-broad-match` is present.

JSON output:

```sh
sudo ./nftracepath run --json --proto udp --src 192.0.2.10 --sport 53000 --dst 198.51.100.53 --dport 53
```

SSH target:

```sh
./nftracepath run \
  --target ssh --ssh-host router.example.net --ssh-user root \
  --proto tcp --src 192.0.2.10 --sport 12345 --dst 198.51.100.20 --dport 443
```

If the SSH user is not root but has passwordless sudo:

```sh
./nftracepath run --target ssh --ssh-host router.example.net --ssh-user admin --sudo ...
```

## Modes

`--mode` chooses how the matching packet is produced or observed. It accepts:

- `listen`: waits for real matching traffic on the target after temporary trace rules are installed. This is the default mode and is the most accurate choice for inbound or forwarded packets, especially when `--in-iface` is used.
- `active`: installs the trace rules, then sends one matching local outbound TCP or UDP packet from the target host. This is useful for local egress smoke tests. It only works with `--target local`, requires `--dport`, and cannot synthesize traffic entering a specific ingress interface, so `--in-iface` should be left empty. `--sport` may be omitted and the OS will pick a source port.

## Backends

`--backend auto` probes both stacks. It chooses iptables when iptables-legacy has real rules, chooses nftables when the nft ruleset has real rules, then falls back to whichever supported stack exists. This avoids selecting an empty nftables ruleset on devices whose active firewall is iptables-legacy.

- nftables: uses a temporary `inet nftracepath_<runid>` table and `nft monitor trace`.
- iptables: uses temporary raw `TRACE` rules, auxiliary `LOG` probes, `iptables-save`, and `journalctl -kf` or `dmesg -w`.

All temporary rules include an `nftracepath:<runid>:...` comment and cleanup runs on normal timeout, error, or Ctrl-C.

## Safety controls

The tool installs kernel TRACE/LOG rules, so broad or high-rate matches can generate a lot of output. These protections are enabled by default:

- `--max-events 200`: stop tracing and clean up after 200 matching events.
- `--trace-limit 10/second`: add kernel-side rate limiting to temporary TRACE/LOG rules.
- `--trace-limit-burst 20`: allow a short initial burst before rate limiting.
- `--allow-broad-match`: required when both `--sport` and `--dport` are omitted.
- `--debug`: include the temporary TRACE/LOG rules in the output for troubleshooting.

For iptables, the temporary rules include `-m limit --limit ... --limit-burst ...`. For nftables, they include `limit rate ... burst ... packets`.

In human output, `--debug` adds a `Debug rules:` section. In JSON output, it adds `debug_rules`.

## Remote testing

Build Linux amd64 artifacts locally, upload them, then run the remote integration script:

```sh
mkdir -p .gotmp .gocache dist
GOTMPDIR=$PWD/.gotmp GOCACHE=$PWD/.gocache GOOS=linux GOARCH=amd64 go build -p 1 -o dist/nftracepath-linux-amd64 ./cmd/nftracepath
GOTMPDIR=$PWD/.gotmp GOCACHE=$PWD/.gocache GOOS=linux GOARCH=amd64 go test -c -p 1 -o dist/trace-linux-amd64.test ./internal/trace

ssh -p 51000 root@192.168.4.24 'mkdir -p /tmp/nftracepath-test'
scp -P 51000 dist/nftracepath-linux-amd64 dist/trace-linux-amd64.test scripts/remote_integration.sh root@192.168.4.24:/tmp/nftracepath-test/
ssh -p 51000 root@192.168.4.24 '/tmp/nftracepath-test/trace-linux-amd64.test -test.v'
ssh -p 51000 root@192.168.4.24 'NFTP_BIN=/tmp/nftracepath-test/nftracepath-linux-amd64 /tmp/nftracepath-test/remote_integration.sh'
```

Some kernels do not expose iptables `LOG`/`TRACE` generated inside network namespaces to the readable kernel log. The integration script detects that and skips iptables namespace cases with a clear message. Run a host-namespace smoke test to validate iptables on those devices:

```sh
ssh -p 51000 root@192.168.4.24 '/tmp/nftracepath-test/nftracepath-linux-amd64 run --target local --backend auto --mode active --timeout 8s --proto udp --src 192.168.4.24 --sport 43002 --dst 192.168.4.254 --dport 53002 --json'
```

## Current scope

- IPv4 TCP/UDP only.
- Source and destination ports are optional in listen mode. Port `0` in JSON means that side was not specified.
- NAT tuple correlation is not implemented; output reports events matching the original five-tuple.
- The tool does not change `nf_log`, sysctl, kernel module, or system logging configuration. If the target does not emit TRACE/LOG lines, it returns a timeout or diagnostic warning.
