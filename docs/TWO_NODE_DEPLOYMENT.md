# Two-Node Deployment Guide

This note documents the lab topology expected by the updated workload configs. It explains how to keep the local and remote hosts in sync and how automation uses the remote execution blocks.

## 1. Topology Overview

| Role | NIC | IP | Notes |
| --- | --- | --- | --- |
| Local server (`ms-host`) | `eth0` | `211.0.0.101/24` | Runs KV/LB/NFV workloads plus instrumentation (baseline, perf, MicroSentinel). |
| Remote generator (`client-host`) | `eth1` | `211.0.0.102/24` | Sends all client requests / traffic to the local host, writes metrics locally before automation copies them back. |

The two servers are directly cabled; no switch sits in between. Leave the link in L2 mode with jumbo frames disabled unless the workload explicitly requires them.

## 2. Repository Sync

Both hosts keep a clone of this repository at `~/MicroSentinel`. Push updates from the local machine to the remote by running:

```bash
rsync -az --delete ~/MicroSentinel/ control_user@211.0.0.102:~/MicroSentinel/
```

Do this before every experiment run so the remote helper scripts match the commit under test.

## 3. Remote Execution Blocks in Configs

Each workload config specifies a `remote` stanza so `workload_runner.py` automatically wraps client/traffic commands with SSH and later pulls their metrics:

```yaml
clients:
  generator: "python3 experiments/workloads/kv/kv_client.py"
  remote:
    host: "211.0.0.102"
    workdir: "~/MicroSentinel"
    metrics_dir: "~/MicroSentinel/artifacts/remote"
```

`host` tells the runner which machine to SSH into, `workdir` selects the directory before launching the command, and `metrics_dir` is where remote JSON files are stored so they can be fetched back after the run.

## 4. Launch Sequence

1. Ensure passwordless SSH from `ms-host` to `client-host` for the account referenced above.
2. On `ms-host`, invoke either the suite runner or the workload runner directly, for example:

```bash
python3 experiments/automation/workload_runner.py --workload kv --mode microsentinel --duration 300
```

3. The runner starts local services + instrumentation, then SSHes into `client-host` to start the load generator. When the run finishes, it fetches JSON artifacts via `scp` and logs the transfers under `<artifact_dir>/remote_fetch.log`.

## 5. Monitoring Expectations

- `mpstat` and `pidstat` cover only the local server; monitor the remote host separately if you need capacity checks.
- Truth logs for NFV and KV workloads reside under `<artifact_dir>/truth/` on the local machine once the fetch completes.
- If a remote copy fails, inspect `remote_fetch.log` to see the exact `scp` command and stderr contents.
