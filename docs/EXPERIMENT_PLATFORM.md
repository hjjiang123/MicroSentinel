# MicroSentinel Experimental Platform

This guide captures the reproducible hardware/software envelope for both nodes in the two-server topology. The goal is that every rerun (or future reader) can reconstruct the exact environment that produced a dataset.

## 1. Topology Snapshot

| Role | Hostname | NIC / IP | Notes |
| --- | --- | --- | --- |
| Local workload + agent (`ms-host`) | `sentinel-a` | `eth0` – `211.0.0.101/24` | Runs KV/LB/NFV servers, MicroSentinel agent, perf instrumentation, ClickHouse sink. |
| Remote generator (`client-host`) | `sentinel-b` | `eth1` – `211.0.0.102/24` | Issues all workload traffic; metrics/logs copied back after each run. Direct DAC cable to `ms-host`. |

Both machines sit in the same rack with a direct 100 GbE copper twinax link; no TOR switches are involved, so latency is dominated by NIC ↔ NIC traversal (~1.2 µs RTT). Keep an updated diagram of cable IDs in the lab wiki so the link can be re-patched consistently.

## 2. Hardware & Firmware

| Field | ms-host | client-host |
| --- | --- | --- |
| Platform | Supermicro X12DPG | Supermicro X12SCZ |
| CPU | 2 × Intel Xeon Gold 6338N (HT on) | Intel Xeon Silver 4314 |
| Memory | 512 GiB DDR4-3200 (8 ch/node) | 256 GiB DDR4-3200 |
| NUMA nodes | 2 (0/1) | 1 |
| NIC | Intel E810-CQDA2 (100 GbE) | Intel E810-XXVDA4 (port 0 dedicated) |
| Storage | Samsung PM9A3 NVMe 3.2 TB | Samsung PM983 1.92 TB |
| BIOS | `2.1b` (custom profile `MS-A`) | `2.1a` |

Document firmware changes (microcode updates, PXE tweaks) in this file whenever you reflash a system.

## 3. Operating System & Kernel

| Component | ms-host | client-host |
| --- | --- | --- |
| Distro | Ubuntu 22.04.4 LTS | Ubuntu 22.04.4 LTS |
| Kernel | `5.15.0-105-generic` + BTF | same |
| Boot args | `intel_pstate=disable nmi_watchdog=0 nosoftlockup` | `intel_pstate=disable` |
| Governor | `performance` via `cpupower frequency-set -g performance` | `performance` |
| NUMA balancing | Disabled (`echo 0 > /proc/sys/kernel/numa_balancing`) | Default |
| Time sync | `chrony` + hardware PTP (slave) | `chrony` (peer) |

Verification commands (run after each kernel update):

```bash
lscpu
numactl --hardware
uname -a
modprobe configs && zgrep BPF /proc/config.gz | grep -E 'BPF|KPROBE|FTRACE'
```

Store the redacted outputs under `experiments/artifacts/<run>/environment/` alongside the run.

## 4. Toolchain & Dependencies

| Component | Version | Install Notes |
| --- | --- | --- |
| GCC / G++ | 12.3 | `sudo apt install build-essential` |
| Clang / LLVM | 17.0.6 | `sudo apt install clang-17 llvm-17 lld-17` |
| libbpf | 1.3 | Built from `https://github.com/libbpf/libbpf` tag `v1.3`; installed under `/usr/local`. |
| libpfm4 | 4.11.0 | Needed for PMU encoding fallback. |
| bpftool | 8.0 | `sudo apt install bpftool` (confirm `bpftool feature probe`). |
| Python | 3.10 | Use system packages + `pip install -r requirements.txt` for workloads. |

After installing/upgrading any dependency, rebuild the repo:

```bash
cmake -S . -B build
cmake --build build -j
```

Generate `experiments/requirements.lock` if additional Python deps are introduced so the remote host can mirror them.

## 5. Network, RSS, and IRQ Pinning

1. **NIC configuration (ms-host)**
   - Confirm queue counts: `sudo ethtool -l eth0` → expect 64 TX/RX queues.
   - Enable symmetric RSS: `sudo ethtool -X eth0 equal 64`.
   - Disable adaptive moderation for deterministic latency: `sudo ethtool -C eth0 rx-usecs 0 rx-frames 0`.

2. **IRQ pinning**
   - Map queue `i` to CPU `i` on NUMA node 0 via:

     ```bash
     for irq in $(grep eth0-TxRx /proc/interrupts | awk '{print $1}' | tr -d ':'); do
       idx=$(grep -n $irq /proc/interrupts | awk -F: '{print $1-1}')
       cpu=$((idx % 32))
       printf "%x" $((1<<cpu)) | sudo tee /proc/irq/$irq/smp_affinity
     done
     ```

   - Persist the mapping with `systemd` drop-ins under `/etc/systemd/system/ms-irq@.service`.

3. **Remote verification**
   - On `client-host`, ensure the dedicated port is up: `ip link show eth1`.
   - Validate reachability and RTT: `ping -f -c 1000 211.0.0.101` (median should stay < 5 µs).

## 6. Repository & SSH Setup

Both machines keep the repo at `~/MicroSentinel`. Sync changes before every run:

```bash
rsync -az --delete ~/MicroSentinel/ control_user@211.0.0.102:~/MicroSentinel/
```

SSH requirements:

- Passwordless auth from `ms-host` → `client-host` using the `control_user` key in `~/.ssh/ms_remote`.
- Add `control_user@211.0.0.102` to `~/.ssh/config` with `IdentitiesOnly yes` so automation can call `ssh`/`scp` without extra flags.

## 7. Pre-run Checklist

1. BIOS → load `MS-A` profile, verify HT + turbo state.
2. Boot kernel with desired cmdline: check `cat /proc/cmdline`.
3. Build artifacts: `cmake --build build --target micro_sentinel_agent`.
4. Generate BPF assets: `make -C bpf vmlinux micro_sentinel_kern.bpf.o`.
5. Copy workload dependencies to remote host (`pip install -r experiments/requirements.txt`).
6. Confirm chrony offset < 5 µs on both hosts (`chronyc tracking`).

Record the SHA (`git rev-parse HEAD`) and store it in each run’s `plan.json` via suite annotations, or keep a `versions.json` file beside artifacts.

## 8. Remote Generator Health

- Monitor CPU headroom with `mpstat -P ALL 1` during a pilot run; keep utilization < 70% to avoid client bottlenecks.
- Ensure `/var/tmp/ms_metrics` (or whatever `metrics_dir` points to) has at least 50 GB free space.
- If traffic scripts require capabilities (e.g., pktgen), pre-load the modules and grant `control_user` passwordless sudo for `modprobe pktgen` + script launch commands.

## 9. Troubleshooting & Logs

| Issue | Checks |
| --- | --- |
| Agent fails to attach eBPF | Confirm `bpftool feature probe` includes `BPF_PROG_TYPE_TRACING`; verify `ulimit -l` ≥ 1024. |
| Remote SSH fails mid-run | Inspect `~/.ssh/known_hosts` for stale keys; regenerate `ssh-keyscan 211.0.0.102 >> ~/.ssh/known_hosts`. |
| NIC link down | `dmesg | grep -i eth0` for flaps; reseat DAC or toggle `ip link set eth0 down/up`. |
| Clock drift | `chronyc sourcestats` > 50 µs indicates a problem; restart `chrony` or switch to `phc2sys` on the NIC PHC. |

Document all deviations or ad-hoc fixes at the bottom of this file with timestamps so future reruns can audit the environment history.
