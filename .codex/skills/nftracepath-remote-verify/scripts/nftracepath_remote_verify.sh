#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  nftracepath_remote_verify.sh --ssh-target USER@HOST [options]

Options:
  --ssh-target TARGET       SSH target or config alias, for example root@192.168.4.24.
  --ssh-port PORT           SSH port. Default: 22.
  --identity-file PATH      SSH identity file.
  --ssh-option OPTION       Extra ssh/scp -o option. May be repeated.
  --remote-dir PATH         Remote work directory. Default: /tmp/nftracepath-test.
  --skip-host-smoke         Skip generated host namespace smoke test.
  --skip-namespace-test     Skip scripts/remote_integration.sh.
  --refresh-scenario        Regenerate cached host smoke script even when signature matches.
  --keep-remote             Keep remote uploaded files.
  -h, --help                Show this help.
USAGE
}

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT_DIR"

SSH_TARGET="${NFTP_SSH_TARGET:-}"
SSH_PORT="${NFTP_SSH_PORT:-22}"
IDENTITY_FILE="${NFTP_IDENTITY_FILE:-}"
REMOTE_DIR="${NFTP_REMOTE_DIR:-/tmp/nftracepath-test}"
RUN_HOST_SMOKE=1
RUN_NAMESPACE_TEST=1
REFRESH_SCENARIO=0
KEEP_REMOTE=0
SSH_OPTIONS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-target)
      SSH_TARGET="${2:-}"
      shift 2
      ;;
    --ssh-port)
      SSH_PORT="${2:-}"
      shift 2
      ;;
    --identity-file)
      IDENTITY_FILE="${2:-}"
      shift 2
      ;;
    --ssh-option)
      SSH_OPTIONS+=("${2:-}")
      shift 2
      ;;
    --remote-dir)
      REMOTE_DIR="${2:-}"
      shift 2
      ;;
    --skip-host-smoke)
      RUN_HOST_SMOKE=0
      shift
      ;;
    --skip-namespace-test)
      RUN_NAMESPACE_TEST=0
      shift
      ;;
    --refresh-scenario)
      REFRESH_SCENARIO=1
      shift
      ;;
    --keep-remote)
      KEEP_REMOTE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$SSH_TARGET" ]]; then
  echo "--ssh-target is required" >&2
  usage >&2
  exit 2
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$ROOT_DIR/dist/remote-test-runs/$timestamp"
CACHE_ROOT="$ROOT_DIR/dist/remote-test-runs/scenario-cache"
mkdir -p "$RUN_DIR" "$CACHE_ROOT"

SUMMARY="$RUN_DIR/summary.md"
DEVICE_INFO="$RUN_DIR/remote-device.env"
PHASE_FILE="$RUN_DIR/current-phase.txt"
CURRENT_LOG_FILE="$RUN_DIR/current-log.txt"
FAILED_PHASE=""
FAILED_COMMAND=""

SSH_CMD=(ssh -p "$SSH_PORT")
SCP_CMD=(scp -P "$SSH_PORT")
if [[ -n "$IDENTITY_FILE" ]]; then
  SSH_CMD+=(-i "$IDENTITY_FILE")
  SCP_CMD+=(-i "$IDENTITY_FILE")
fi
if [[ "${#SSH_OPTIONS[@]}" -gt 0 ]]; then
  for opt in "${SSH_OPTIONS[@]}"; do
    SSH_CMD+=(-o "$opt")
    SCP_CMD+=(-o "$opt")
  done
fi

note_phase() {
  printf '%s\n' "$1" >"$PHASE_FILE"
  if [[ -n "${2:-}" ]]; then
    printf '%s\n' "$2" >"$CURRENT_LOG_FILE"
  fi
}

run_logged() {
  local phase="$1"
  local logfile="$2"
  shift 2
  note_phase "$phase" "$logfile"
  printf '## %s\n$' "$phase" >>"$logfile"
  printf ' %q' "$@" >>"$logfile"
  printf '\n' >>"$logfile"
  "$@" >>"$logfile" 2>&1
}

run_remote_logged() {
  local phase="$1"
  local logfile="$2"
  local remote_command="$3"
  note_phase "$phase" "$logfile"
  {
    printf '## %s\n' "$phase"
    printf '$ ssh %s %q\n' "$SSH_TARGET" "$remote_command"
  } >>"$logfile"
  "${SSH_CMD[@]}" "$SSH_TARGET" "$remote_command" >>"$logfile" 2>&1
}

on_error() {
  local exit_code=$?
  local current_log=""
  FAILED_PHASE="$(cat "$PHASE_FILE" 2>/dev/null || true)"
  current_log="$(cat "$CURRENT_LOG_FILE" 2>/dev/null || true)"
  {
    echo "# nftracepath remote verification failed"
    echo
    echo "- Exit code: $exit_code"
    echo "- Failed phase: ${FAILED_PHASE:-unknown}"
    echo "- Target: $SSH_TARGET"
    echo "- Log directory: $RUN_DIR"
    echo
    if [[ -s "$DEVICE_INFO" ]]; then
      echo "## Device information"
      sed 's/^/- /' "$DEVICE_INFO"
      echo
    fi
    if [[ -n "$current_log" && -s "$current_log" ]]; then
      echo "## stdout/stderr summary"
      echo
      echo '```text'
      tail -n 80 "$current_log"
      echo '```'
      echo
    fi
    echo "## Next step"
    echo "Inspect the phase log in this directory, summarize stdout/stderr, then propose a fix before modifying code."
  } | tee "$SUMMARY"
  exit "$exit_code"
}
trap on_error ERR

detect_go_arch() {
  local machine="$1"
  GOARCH=""
  GOARM=""
  case "$machine" in
    x86_64|amd64)
      GOARCH="amd64"
      ;;
    aarch64|arm64)
      GOARCH="arm64"
      ;;
    armv7l|armv7*)
      GOARCH="arm"
      GOARM="7"
      ;;
    armv6l|armv6*)
      GOARCH="arm"
      GOARM="6"
      ;;
    i386|i686)
      GOARCH="386"
      ;;
    riscv64)
      GOARCH="riscv64"
      ;;
    *)
      echo "unsupported remote architecture: $machine" >&2
      return 1
      ;;
  esac
}

generate_host_smoke_script() {
  local output="$1"
  cat >"$output" <<'REMOTE_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BIN="${NFTP_BIN:?NFTP_BIN is required}"
RUN_ID="${NFTP_RUN_ID:-$(date +%s)-$$}"
SHORT_ID="$(printf '%s' "$RUN_ID" | tr -cd '[:alnum:]' | tail -c 6)"
OCTET=$(( ( $(date +%s) + $$ ) % 200 + 20 ))
BR="br-nftp-${SHORT_ID}"
NS="nftp-host-${SHORT_ID}"
VH="vh${SHORT_ID}"
VN="vn${SHORT_ID}"
TABLE="nftp_host_${SHORT_ID}"
COMMENT="nftp-host-smoke:${SHORT_ID}"
BR_IP="198.18.${OCTET}.1"
NS_IP="198.18.${OCTET}.2"
SPORT=43101
DPORT=53101
BASE="/tmp/nftracepath-host-smoke-${RUN_ID}"
mkdir -p "$BASE"

cleanup() {
  set +e
  nft delete table inet "$TABLE" >/dev/null 2>&1
  if command -v iptables-legacy >/dev/null 2>&1; then
    iptables-legacy -D INPUT -p udp -s "$NS_IP" --sport "$SPORT" -d "$BR_IP" --dport "$DPORT" -m comment --comment "$COMMENT" -j ACCEPT >/dev/null 2>&1
  fi
  ip netns del "$NS" >/dev/null 2>&1
  ip link del "$BR" >/dev/null 2>&1
  rm -rf "$BASE"
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

has_real_iptables_legacy_rules() {
  command -v iptables-legacy-save >/dev/null 2>&1 || return 1
  iptables-legacy-save 2>/dev/null | grep -E '^-A ' >/dev/null 2>&1
}

has_real_nft_rules() {
  command -v nft >/dev/null 2>&1 || return 1
  nft list ruleset 2>/dev/null | grep -E '^[[:space:]]*(table|chain|hook|ip|meta|udp|tcp|counter)' >/dev/null 2>&1
}

select_stack() {
  if has_real_iptables_legacy_rules; then
    echo "iptables"
    return
  fi
  if has_real_nft_rules; then
    echo "nft"
    return
  fi
  if command -v nft >/dev/null 2>&1; then
    echo "nft"
    return
  fi
  if command -v iptables-legacy >/dev/null 2>&1; then
    echo "iptables"
    return
  fi
  echo "none"
}

send_udp() {
  ip netns exec "$NS" python3 - "$NS_IP" "$SPORT" "$BR_IP" "$DPORT" <<'PY'
import socket
import sys

src, sport, dst, dport = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, sport))
s.settimeout(1)
s.sendto(b"nftracepath-host-smoke\n", (dst, dport))
s.close()
PY
}

validate_json() {
  local json_file="$1"
  local stack="$2"
  local comment="$3"
  python3 - "$json_file" "$stack" "$comment" <<'PY'
import json
import sys

path, stack, comment = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
events = data.get("events") or []
outcome = data.get("outcome")
backend = data.get("backend")
if outcome not in {"local", "egress", "drop"}:
    raise SystemExit(f"unexpected outcome {outcome!r}: {data}")
if not events:
    raise SystemExit(f"expected trace events: {data}")
raw = "\n".join(
    str(e.get("raw", "")) + "\n" +
    str(e.get("rule", "")) + "\n" +
    str((e.get("rule_ref") or {}).get("rule", ""))
    for e in events
)
if comment not in raw:
    raise SystemExit(f"expected generated test rule comment {comment!r} in trace events: {data}")
if stack == "iptables" and backend != "iptables":
    raise SystemExit(f"expected backend iptables, got {backend!r}")
if stack == "nft" and backend != "nft":
    raise SystemExit(f"expected backend nft, got {backend!r}")
print(f"HOST_SMOKE_OUTCOME={outcome}")
print(f"HOST_SMOKE_BACKEND={backend}")
print(f"HOST_SMOKE_EVENTS={len(events)}")
PY
}

require_cmd ip
require_cmd python3

HOSTNAME="$(hostname 2>/dev/null || true)"
KERNEL="$(uname -srmo 2>/dev/null || uname -a)"
MACHINE="$(uname -m)"
NFT_AVAILABLE=no
IPTABLES_LEGACY_AVAILABLE=no
command -v nft >/dev/null 2>&1 && NFT_AVAILABLE=yes
command -v iptables-legacy >/dev/null 2>&1 && IPTABLES_LEGACY_AVAILABLE=yes
STACK="$(select_stack)"
if [[ "$STACK" == "none" ]]; then
  echo "no supported netfilter stack found" >&2
  exit 2
fi
if [[ "$STACK" == "nft" ]]; then
  require_cmd nft
else
  require_cmd iptables-legacy
fi

ip link add "$BR" type bridge
ip addr add "${BR_IP}/30" dev "$BR"
ip link set "$BR" up
ip netns add "$NS"
ip link add "$VH" type veth peer name "$VN"
ip link set "$VH" master "$BR"
ip link set "$VH" up
ip link set "$VN" netns "$NS"
ip -n "$NS" link set "$VN" name eth0
ip -n "$NS" addr add "${NS_IP}/30" dev eth0
ip -n "$NS" link set lo up
ip -n "$NS" link set eth0 up

if [[ "$STACK" == "nft" ]]; then
  nft -f - <<NFT
add table inet ${TABLE}
add chain inet ${TABLE} input { type filter hook input priority 0; policy accept; }
add rule inet ${TABLE} input ip saddr ${NS_IP} ip daddr ${BR_IP} udp sport ${SPORT} udp dport ${DPORT} counter accept comment "${COMMENT}"
NFT
  RULE_DESC="nft inet ${TABLE} input exact udp ${NS_IP}:${SPORT} -> ${BR_IP}:${DPORT} accept comment ${COMMENT}"
  BACKEND="nft"
else
  iptables-legacy -I INPUT 1 -p udp -s "$NS_IP" --sport "$SPORT" -d "$BR_IP" --dport "$DPORT" -m comment --comment "$COMMENT" -j ACCEPT
  RULE_DESC="iptables-legacy INPUT exact udp ${NS_IP}:${SPORT} -> ${BR_IP}:${DPORT} ACCEPT comment ${COMMENT}"
  BACKEND="iptables"
fi

OUT="$BASE/host-smoke.json"
ERR="$BASE/host-smoke.err"
"$BIN" run \
  --target local \
  --backend "$BACKEND" \
  --mode listen \
  --timeout 8s \
  --proto udp \
  --src "$NS_IP" \
  --sport "$SPORT" \
  --dst "$BR_IP" \
  --dport "$DPORT" \
  --in-iface "$BR" \
  --json >"$OUT" 2>"$ERR" &
TRACE_PID=$!
sleep 1
send_udp
if ! wait "$TRACE_PID"; then
  echo "host smoke nftracepath failed" >&2
  cat "$ERR" >&2 || true
  cat "$OUT" >&2 || true
  exit 1
fi

validate_json "$OUT" "$BACKEND" "$COMMENT"

cat <<SUMMARY
REMOTE_HOSTNAME=${HOSTNAME}
REMOTE_KERNEL=${KERNEL}
REMOTE_MACHINE=${MACHINE}
NFT_AVAILABLE=${NFT_AVAILABLE}
IPTABLES_LEGACY_AVAILABLE=${IPTABLES_LEGACY_AVAILABLE}
SELECTED_STACK=${BACKEND}
TEST_RULE=${RULE_DESC}
TOPOLOGY=netns ${NS} eth0 ${NS_IP} -- veth ${VN}/${VH} -- bridge ${BR} ${BR_IP} -- host INPUT
TOPOLOGY_DIAGRAM=netns(${NS}, eth0 ${NS_IP}) -> veth(${VN}/${VH}) -> bridge(${BR}, ${BR_IP}) -> host INPUT
SUMMARY
REMOTE_SCRIPT
}

write_success_summary() {
  local host_smoke_log="$1"
  local namespace_log="$2"
  local remote_test_log="$3"
  local stack
  local test_rule
  local topology
  stack="$(grep '^SELECTED_STACK=' "$host_smoke_log" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
  test_rule="$(grep '^TEST_RULE=' "$host_smoke_log" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
  topology="$(grep '^TOPOLOGY_DIAGRAM=' "$host_smoke_log" 2>/dev/null | tail -n 1 | cut -d= -f2- || true)"
  {
    echo "# nftracepath remote verification passed"
    echo
    echo "- Target: $SSH_TARGET"
    echo "- Remote directory: $REMOTE_DIR"
    echo "- Log directory: $RUN_DIR"
    echo
    echo "## Device information"
    sed 's/^/- /' "$DEVICE_INFO"
    echo
    echo "## Backend"
    echo "- Host smoke selected stack: ${stack:-unknown}"
    echo
    echo "## Temporary test rule"
    echo "- ${test_rule:-see host-smoke.log}"
    echo
    echo "## Logical test topology"
    echo
    echo '```text'
    if [[ -n "$topology" ]]; then
      echo "$topology"
    else
      echo "netns -> veth -> bridge -> host INPUT"
    fi
    echo '```'
    echo
    echo "## Logs"
    echo "- Remote Go test: $remote_test_log"
    echo "- Namespace integration: $namespace_log"
    echo "- Host smoke: $host_smoke_log"
  } | tee "$SUMMARY"
}

LOCAL_TEST_LOG="$RUN_DIR/local-go-test.log"
BUILD_LOG="$RUN_DIR/build.log"
REMOTE_INFO_LOG="$RUN_DIR/remote-info.log"
UPLOAD_LOG="$RUN_DIR/upload.log"
REMOTE_TEST_LOG="$RUN_DIR/remote-go-test.log"
NAMESPACE_LOG="$RUN_DIR/remote-namespace-integration.log"
HOST_SMOKE_LOG="$RUN_DIR/remote-host-smoke.log"

run_logged "local go test" "$LOCAL_TEST_LOG" go test ./...

note_phase "remote device detection" "$REMOTE_INFO_LOG"
{
  echo "## remote device detection"
  "${SSH_CMD[@]}" "$SSH_TARGET" "set -e; echo HOSTNAME=\$(hostname 2>/dev/null || true); echo KERNEL=\$(uname -srmo 2>/dev/null || uname -a); echo MACHINE=\$(uname -m); echo OS=\$(cat /etc/os-release 2>/dev/null | tr '\n' ';' || true); command -v ip >/dev/null && echo IP_AVAILABLE=yes || echo IP_AVAILABLE=no; command -v nft >/dev/null && echo NFT_AVAILABLE=yes || echo NFT_AVAILABLE=no; command -v iptables-legacy >/dev/null && echo IPTABLES_LEGACY_AVAILABLE=yes || echo IPTABLES_LEGACY_AVAILABLE=no; command -v python3 >/dev/null && echo PYTHON3_AVAILABLE=yes || echo PYTHON3_AVAILABLE=no" | tee "$DEVICE_INFO"
} >>"$REMOTE_INFO_LOG" 2>&1

machine="$(grep '^MACHINE=' "$DEVICE_INFO" | tail -n 1 | cut -d= -f2-)"
detect_go_arch "$machine"
{
  echo "GOOS=linux"
  echo "GOARCH=$GOARCH"
  [[ -n "$GOARM" ]] && echo "GOARM=$GOARM"
} >>"$DEVICE_INFO"

BIN_NAME="nftracepath-linux-${GOARCH}${GOARM:+v$GOARM}"
TEST_NAME="trace-linux-${GOARCH}${GOARM:+v$GOARM}.test"
BIN_PATH="$RUN_DIR/$BIN_NAME"
TEST_PATH="$RUN_DIR/$TEST_NAME"
HOST_SCRIPT="$RUN_DIR/generated_host_smoke.sh"

note_phase "cross compile" "$BUILD_LOG"
{
  echo "## build nftracepath"
  build_env=(env GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0)
  if [[ -n "$GOARM" ]]; then
    build_env+=(GOARM="$GOARM")
  fi
  "${build_env[@]}" go build -p 1 -o "$BIN_PATH" ./cmd/nftracepath
  echo "## build internal/trace test binary"
  "${build_env[@]}" go test -c -p 1 -o "$TEST_PATH" ./internal/trace
} >>"$BUILD_LOG" 2>&1

SCENARIO_SIGNATURE_SOURCE="$RUN_DIR/scenario-signature-source.txt"
{
  echo "scenario_version=v2"
  echo "ssh_target=$SSH_TARGET"
  echo "remote_dir=$REMOTE_DIR"
  echo "run_host_smoke=$RUN_HOST_SMOKE"
  echo "run_namespace_test=$RUN_NAMESPACE_TEST"
  cat "$DEVICE_INFO"
} >"$SCENARIO_SIGNATURE_SOURCE"
if command -v shasum >/dev/null 2>&1; then
  scenario_signature="$(shasum "$SCENARIO_SIGNATURE_SOURCE" | awk '{print $1}')"
else
  scenario_signature="$(sha1sum "$SCENARIO_SIGNATURE_SOURCE" | awk '{print $1}')"
fi
scenario_cache_dir="$CACHE_ROOT/$scenario_signature"
cached_host_script="$scenario_cache_dir/generated_host_smoke.sh"
mkdir -p "$scenario_cache_dir"
if [[ "$REFRESH_SCENARIO" -eq 0 && -s "$cached_host_script" ]]; then
  cp "$cached_host_script" "$HOST_SCRIPT"
  echo "reused cached host smoke script: $cached_host_script" >"$RUN_DIR/scenario-cache.txt"
else
  generate_host_smoke_script "$HOST_SCRIPT"
  cp "$HOST_SCRIPT" "$cached_host_script"
  echo "generated host smoke script and cached it: $cached_host_script" >"$RUN_DIR/scenario-cache.txt"
fi
chmod +x "$HOST_SCRIPT"

run_remote_logged "prepare remote directory" "$UPLOAD_LOG" "mkdir -p '$REMOTE_DIR'"
note_phase "upload artifacts" "$UPLOAD_LOG"
{
  printf '$ scp artifacts to %s:%s\n' "$SSH_TARGET" "$REMOTE_DIR"
  "${SCP_CMD[@]}" "$BIN_PATH" "$TEST_PATH" "$HOST_SCRIPT" "$SSH_TARGET:$REMOTE_DIR/" 
  if [[ -f "$ROOT_DIR/scripts/remote_integration.sh" ]]; then
    "${SCP_CMD[@]}" "$ROOT_DIR/scripts/remote_integration.sh" "$SSH_TARGET:$REMOTE_DIR/"
  fi
} >>"$UPLOAD_LOG" 2>&1

run_remote_logged "remote Go test binary" "$REMOTE_TEST_LOG" "cd '$REMOTE_DIR' && chmod +x '$TEST_NAME' && './$TEST_NAME' -test.v"

if [[ "$RUN_NAMESPACE_TEST" -eq 1 && -f "$ROOT_DIR/scripts/remote_integration.sh" ]]; then
  run_remote_logged "remote namespace integration" "$NAMESPACE_LOG" "cd '$REMOTE_DIR' && chmod +x '$BIN_NAME' remote_integration.sh && NFTP_BIN='$REMOTE_DIR/$BIN_NAME' './remote_integration.sh'"
else
  echo "namespace integration skipped" >"$NAMESPACE_LOG"
fi

if [[ "$RUN_HOST_SMOKE" -eq 1 ]]; then
  run_remote_logged "remote host namespace smoke" "$HOST_SMOKE_LOG" "cd '$REMOTE_DIR' && chmod +x '$BIN_NAME' generated_host_smoke.sh && NFTP_BIN='$REMOTE_DIR/$BIN_NAME' './generated_host_smoke.sh'"
else
  echo "host smoke skipped" >"$HOST_SMOKE_LOG"
fi

if [[ "$KEEP_REMOTE" -eq 0 ]]; then
  run_remote_logged "remote cleanup uploaded artifacts" "$RUN_DIR/remote-cleanup.log" "rm -f '$REMOTE_DIR/$BIN_NAME' '$REMOTE_DIR/$TEST_NAME' '$REMOTE_DIR/generated_host_smoke.sh' '$REMOTE_DIR/remote_integration.sh'"
fi

trap - ERR
write_success_summary "$HOST_SMOKE_LOG" "$NAMESPACE_LOG" "$REMOTE_TEST_LOG"
