#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$repo_root/build"
cmake -S "$repo_root" -B "$repo_root/build"
cmake --build "$repo_root/build"
(cd "$repo_root/bpf" && make)
echo "Environment ready. Agent binary at build/agent/micro_sentinel_agent"
