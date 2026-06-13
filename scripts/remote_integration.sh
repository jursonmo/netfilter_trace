#!/usr/bin/env bash
set -euo pipefail

BIN="${NFTP_BIN:-./nftracepath}"
if command -v readlink >/dev/null 2>&1; then
  BIN="$(readlink -f "$BIN")"
fi

if [[ ! -x "$BIN" ]]; then
  echo "nftracepath binary not executable: $BIN" >&2
  exit 2
fi

RUN_ID="${NFTP_RUN_ID:-$(date +%s)-$$}"
SHORT_ID="$(printf '%s' "$RUN_ID" | tr -cd '[:alnum:]' | tail -c 6)"
BASE="/tmp/nftracepath-it-${RUN_ID}"
NS_C="nftp-c-${RUN_ID}"
NS_R="nftp-r-${RUN_ID}"
NS_S="nftp-s-${RUN_ID}"
V_C="vc${SHORT_ID}"
V_R0="vr0${SHORT_ID}"
V_R1="vr1${SHORT_ID}"
V_S="vs${SHORT_ID}"
NFT_DROP_TABLE="nftp_drop_${SHORT_ID}"
BACKENDS="${NFTP_BACKENDS:-iptables nft}"
mkdir -p "$BASE"

cleanup() {
  set +e
  pkill -f "ip netns exec ${NS_C} nc" >/dev/null 2>&1
  pkill -f "ip netns exec ${NS_S} nc" >/dev/null 2>&1
  ip netns del "$NS_C" >/dev/null 2>&1
  ip netns del "$NS_R" >/dev/null 2>&1
  ip netns del "$NS_S" >/dev/null 2>&1
  rm -rf "$BASE"
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

require_cmd ip
require_cmd iptables
require_cmd nft
require_cmd python3

setup_topology() {
  ip netns add "$NS_C"
  ip netns add "$NS_R"
  ip netns add "$NS_S"

  ip link add "$V_C" type veth peer name "$V_R0"
  ip link add "$V_R1" type veth peer name "$V_S"
  ip link set "$V_C" netns "$NS_C"
  ip link set "$V_R0" netns "$NS_R"
  ip link set "$V_R1" netns "$NS_R"
  ip link set "$V_S" netns "$NS_S"

  ip -n "$NS_C" link set "$V_C" name c0
  ip -n "$NS_R" link set "$V_R0" name r0
  ip -n "$NS_R" link set "$V_R1" name r1
  ip -n "$NS_S" link set "$V_S" name s0

  ip -n "$NS_C" addr add 10.88.1.2/24 dev c0
  ip -n "$NS_R" addr add 10.88.1.1/24 dev r0
  ip -n "$NS_R" addr add 10.88.2.1/24 dev r1
  ip -n "$NS_S" addr add 10.88.2.2/24 dev s0

  ip -n "$NS_C" link set lo up
  ip -n "$NS_C" link set c0 up
  ip -n "$NS_R" link set lo up
  ip -n "$NS_R" link set r0 up
  ip -n "$NS_R" link set r1 up
  ip -n "$NS_S" link set lo up
  ip -n "$NS_S" link set s0 up

  ip -n "$NS_C" route add default via 10.88.1.1
  ip -n "$NS_S" route add default via 10.88.2.1
  ip netns exec "$NS_R" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$NS_R" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$NS_R" sh -c 'echo nf_log_ipv4 > /proc/sys/net/netfilter/nf_log/2' >/dev/null 2>&1 || true
  ip netns exec "$NS_S" sh -c 'echo nf_log_ipv4 > /proc/sys/net/netfilter/nf_log/2' >/dev/null 2>&1 || true
}

send_udp() {
  local sport="$1"
  local dst="$2"
  local dport="$3"
  ip netns exec "$NS_C" python3 - "$sport" "$dst" "$dport" <<'PY'
import socket
import sys

sport = int(sys.argv[1])
dst = sys.argv[2]
dport = int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.88.1.2", sport))
s.settimeout(1)
s.sendto(b"nftracepath-it\n", (dst, dport))
s.close()
PY
}

assert_json() {
  local file="$1"
  local expected="$2"
  python3 - "$file" "$expected" <<'PY'
import json
import sys

path, expected = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
outcome = data.get("outcome")
events = data.get("events") or []
if outcome != expected:
    raise SystemExit(f"expected outcome {expected!r}, got {outcome!r}: {data}")
if expected != "timeout" and not events:
    raise SystemExit(f"expected trace events for outcome {expected!r}: {data}")
print(f"ok outcome={outcome} events={len(events)} backend={data.get('backend')}")
PY
}

run_trace_case() {
  local name="$1"
  local ns="$2"
  local backend="$3"
  local expected="$4"
  local sport="$5"
  local dport="$6"
  local in_iface="$7"
  local trigger="$8"
  local out="${BASE}/${name}-${backend}.json"
  local err="${BASE}/${name}-${backend}.err"

  echo "case ${name} backend=${backend}"
  ip netns exec "$ns" "$BIN" run \
    --target local \
    --backend "$backend" \
    --mode listen \
    --timeout 8s \
    --proto udp \
    --src 10.88.1.2 \
    --sport "$sport" \
    --dst 10.88.2.2 \
    --dport "$dport" \
    --in-iface "$in_iface" \
    --json >"$out" 2>"$err" &
  local pid=$!
  sleep 1
  if [[ "$trigger" == "send" ]]; then
    send_udp "$sport" 10.88.2.2 "$dport"
  fi
  if ! wait "$pid"; then
    echo "trace command failed for ${name}/${backend}" >&2
    cat "$err" >&2 || true
    cat "$out" >&2 || true
    return 1
  fi
  assert_json "$out" "$expected"
}

run_drop_case() {
  local backend="$1"
  local sport=41003
  local dport=51003
  if [[ "$backend" == "iptables" ]]; then
    ip netns exec "$NS_R" iptables -I FORWARD 1 -p udp -s 10.88.1.2 --sport "$sport" -d 10.88.2.2 --dport "$dport" -j DROP
    run_trace_case drop "$NS_R" "$backend" drop "$sport" "$dport" r0 send
    ip netns exec "$NS_R" iptables -D FORWARD -p udp -s 10.88.1.2 --sport "$sport" -d 10.88.2.2 --dport "$dport" -j DROP >/dev/null 2>&1 || true
    return
  fi

  ip netns exec "$NS_R" nft -f - <<NFT
add table inet ${NFT_DROP_TABLE}
add chain inet ${NFT_DROP_TABLE} drop_forward { type filter hook forward priority 0; policy accept; }
add rule inet ${NFT_DROP_TABLE} drop_forward ip saddr 10.88.1.2 ip daddr 10.88.2.2 udp sport ${sport} udp dport ${dport} drop
NFT
  run_trace_case drop "$NS_R" "$backend" drop "$sport" "$dport" r0 send
  ip netns exec "$NS_R" nft delete table inet "$NFT_DROP_TABLE" >/dev/null 2>&1 || true
}

iptables_netns_logs_available() {
  local prefix="NFTP-PREFLIGHT-${SHORT_ID}"
  ip netns exec "$NS_R" iptables -t mangle -A POSTROUTING -p udp -s 10.88.1.2 --sport 41999 -d 10.88.2.2 --dport 51999 -j LOG --log-prefix "$prefix " >/dev/null 2>&1
  send_udp 41999 10.88.2.2 51999
  sleep 1
  ip netns exec "$NS_R" iptables -t mangle -D POSTROUTING -p udp -s 10.88.1.2 --sport 41999 -d 10.88.2.2 --dport 51999 -j LOG --log-prefix "$prefix " >/dev/null 2>&1 || true
  dmesg | tail -n 200 | grep -q "$prefix"
}

setup_topology

if [[ " $BACKENDS " == *" iptables "* ]] && ! iptables_netns_logs_available; then
  echo "skip backend=iptables: kernel log does not expose iptables LOG/TRACE from network namespaces on this target"
  BACKENDS="$(printf '%s\n' $BACKENDS | grep -v '^iptables$' | xargs || true)"
fi

if [[ -z "$BACKENDS" ]]; then
  echo "no runnable namespace backends after preflight" >&2
  exit 1
fi

for backend in $BACKENDS; do
  run_trace_case forward "$NS_R" "$backend" egress 41001 51001 r0 send
  run_trace_case local "$NS_S" "$backend" local 41002 51002 s0 send
  run_drop_case "$backend"
  run_trace_case timeout "$NS_R" "$backend" timeout 41004 51004 r0 none
done

echo "remote integration tests passed"
