---
name: nftracepath-remote-verify
description: Deploy and verify the nftracepath Go project on a user-specified remote Linux device after code changes. Use when Codex needs to run local tests, detect the remote host architecture, cross-compile Linux artifacts, upload them over SSH/SCP, run remote Go test binaries, generate or reuse remote netfilter validation scripts, add temporary namespace and host smoke-test rules, collect full logs, summarize success or failure, and propose fixes before modifying code.
---

# nftracepath Remote Verify

## Overview

Use this skill to validate recent `nftracepath` changes against a real remote Linux target. Do not hard-code the remote login details in the skill; require the user to provide the SSH target or enough SSH options each time the skill is invoked.

The default automation script is `scripts/nftracepath_remote_verify.sh`. Prefer running it before hand-writing ad hoc deployment commands.

## Required Input

Obtain the remote login method from the user for each run. Accept normal SSH details such as:

```sh
.codex/skills/nftracepath-remote-verify/scripts/nftracepath_remote_verify.sh \
  --ssh-target root@192.168.4.24 \
  --ssh-port 51000
```

If the login uses aliases, keys, jump hosts, or custom SSH options, pass them with `--ssh-target`, `--identity-file`, and repeated `--ssh-option` values. Ask only for missing login information. Do not ask the user for the remote CPU architecture; detect it with `uname -m` and cross-compile accordingly.

## Verification Workflow

Run the bundled script from the repository root. It performs the standard workflow:

1. Run local `go test ./...`.
2. Connect to the remote host and collect device information.
3. Detect remote architecture and map it to `GOOS=linux` and the appropriate `GOARCH`/`GOARM`.
4. Cross-compile `cmd/nftracepath`.
5. Cross-compile the remote Go test binary for `./internal/trace`.
6. Upload artifacts and test scripts to the remote directory.
7. Run the remote Go test binary.
8. Run the existing namespace integration test script when available.
9. Generate or reuse a host smoke-test script for unchanged remote/scenario information.
10. Run host smoke testing with a temporary bridge/veth/netns topology and exact-match netfilter test rules.
11. Save full logs under `dist/remote-test-runs/<timestamp>/`.
12. Print a concise success or failure summary.

## Remote Test Topologies

Exercise both project-provided and generated scenarios.

Use the repository integration script `scripts/remote_integration.sh` for the multi-namespace forward/local/drop/timeout checks. It creates temporary network namespaces and adds strict nftables or iptables test rules for validation.

For host namespace smoke testing, generate a script that builds this logical topology:

```text
netns nftp-host-<id>
  eth0 198.18.x.2
    |
    | veth pair
    |
bridge br-nftp-<id> 198.18.x.1
    |
host namespace INPUT path
```

The generated host smoke test must:

- Create a temporary bridge.
- Create a veth pair.
- Attach one end to the bridge.
- Move the other end into a temporary namespace.
- Send a UDP packet from the namespace with a fixed source port and destination port.
- Add an exact-match temporary nftables or iptables-legacy test rule on the host namespace.
- Run `nftracepath` against that exact tuple.
- Confirm that trace output contains events and that the generated test rule was matched.
- Clean up all namespaces, links, tables, and rules on exit.

Use reserved benchmark/test addresses such as `198.18.0.0/15` for generated topology addresses. Avoid touching production routes or broad firewall matches.

## Backend and Device Reporting

On every successful run, report at least:

- Target SSH endpoint.
- Remote hostname, kernel, OS string if available, and `uname -m`.
- Detected Go architecture.
- Detected netfilter stack used for the host smoke test: `nft` or `iptables-legacy`.
- Whether `nft`, `iptables-legacy`, `ip`, and `python3` are available.
- Which temporary test rules were added.
- The logical topology diagram used for testing.
- The full local log directory.

On failure, still report all device and backend information that was collected before the failure.

## Failure Handling

When a verification step fails:

1. Identify the failed phase and command.
2. Summarize stdout/stderr without hiding the full log path.
3. Read `references/failure-analysis.md` for common causes and targeted diagnostic checks.
4. Propose a concrete fix plan.
5. Stop and wait for the user's explicit approval before editing project code.

After the user approves the plan, make the minimal code or script changes, rerun the verification script, and report the new result.

## Safety Rules

- Never persist credentials in the skill, repository, logs, or generated scripts.
- Use exact five-tuple matches for all host namespace test rules.
- Keep all generated remote resources under the selected remote temp directory.
- Prefer `nft` when neither nftables nor iptables-legacy has existing real rules, but report the reason.
- Treat skipped iptables namespace cases as warnings only when the script explicitly explains that the kernel does not expose namespace iptables LOG/TRACE output.
- Do not modify code after a failed verification unless the user has approved the proposed fix.
