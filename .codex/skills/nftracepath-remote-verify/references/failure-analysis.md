# nftracepath Remote Verification Failure Analysis

Use this reference only after a remote verification failure or suspicious warning.

## Common failure modes

### Remote prerequisites missing

Symptoms:

- `missing required command: ip`
- `missing required command: nft`
- `missing required command: iptables`
- `missing required command: python3`

Checks:

- Run `command -v ip nft iptables iptables-legacy python3`.
- Confirm the remote user is root or has passwordless sudo if the workflow is adapted to sudo.

Likely fixes:

- Install the missing package on the test target.
- Adjust the generated scenario to skip unavailable backends only when the requested coverage still makes sense.

### Architecture mapping failed

Symptoms:

- `unsupported remote architecture`
- Uploaded binary exits with `Exec format error`.

Checks:

- Inspect remote `uname -m`.
- Confirm the script maps the value to `GOARCH` and optional `GOARM`.

Likely fixes:

- Add an architecture mapping to the verification script.
- Rebuild the binary and test artifact for the detected architecture.

### iptables namespace logs unavailable

Symptoms:

- Namespace integration reports `skip backend=iptables`.
- iptables tests time out in network namespaces while nft passes.

Checks:

- Confirm whether the kernel exposes namespace-generated iptables LOG/TRACE lines to readable kernel logs.
- Check `dmesg`, `journalctl -k`, and `/proc/sys/net/netfilter/nf_log/2`.

Likely fixes:

- Treat the namespace skip as an environment limitation if the script reports it clearly.
- Use host-namespace smoke testing for iptables-legacy coverage on that target.

### nft versus iptables-legacy backend mismatch

Symptoms:

- A rule is visible in `iptables -L` but not `iptables-legacy -L`.
- `--backend iptables` times out while `--backend nft` sees the rule.

Checks:

- Compare `iptables --version`, `iptables-legacy-save`, and `nft list ruleset`.
- Remember that `iptables-nft` compatibility rules are observed through nft trace, not legacy TRACE logs.

Likely fixes:

- Use `--backend nft` for iptables-nft compatibility rules.
- Fix backend auto-detection only if it contradicts the repository rules documented in `README.md` and `moreinfo.md`.

### Host smoke packet not matching the test rule

Symptoms:

- Host smoke JSON has no events.
- Host smoke JSON lacks an event containing the generated rule comment.
- Outcome is `timeout`.

Checks:

- Verify bridge, veth, namespace, and addresses were created.
- Confirm source IP, destination IP, source port, destination port, protocol, and ingress interface match exactly.
- Inspect generated rule text and nftracepath command line in the run logs.

Likely fixes:

- Correct the generated topology interface name passed as `--in-iface`.
- Correct tuple generation or sender binding.
- Adjust parsing only after confirming the kernel trace output is valid.

### Cleanup failure

Symptoms:

- Repeated runs fail creating a bridge, namespace, table, or chain that already exists.

Checks:

- Inspect remote `ip netns list`, `ip link show`, `nft list ruleset`, and iptables rule lists for stale `nftp` names/comments.

Likely fixes:

- Improve trap cleanup in generated scripts.
- Manually remove stale resources only after confirming they belong to prior verification runs.

## Reporting expectations

When reporting failure to the user, include:

- Failed phase.
- Failed command.
- Short stderr/stdout summary.
- Full log directory.
- Device information collected before failure.
- Backend selected or detection state.
- Proposed fix plan.

Do not modify project code until the user approves the proposed fix plan.
