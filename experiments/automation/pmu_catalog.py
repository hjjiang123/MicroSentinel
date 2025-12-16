"""Static PMU descriptor catalog for MicroSentinel automation.

This helper translates human-friendly aliases (the ones used in suite YAML files)
into fully specified perf_event attributes so we can drive the agent control plane
via `/api/v1/pmu-config`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Minimal subset of `linux/perf_event.h` constants that we need when crafting
# perf_event_attr structures from user-friendly aliases.
PERF_TYPE_HARDWARE = 0
PERF_TYPE_HW_CACHE = 3
PERF_TYPE_RAW = 4

PERF_COUNT_HW_CPU_CYCLES = 0
PERF_COUNT_HW_BRANCH_MISSES = 5

PERF_COUNT_HW_CACHE_LL = 3
PERF_COUNT_HW_CACHE_OP_READ = 0
PERF_COUNT_HW_CACHE_RESULT_MISS = 1

# Logical event identifiers copied from `ms_common.h` so that user-land and the
# eBPF side stay consistent when classifying samples.
MS_EVT_L3_MISS = 1
MS_EVT_BRANCH_MISPRED = 2
MS_EVT_XSNP_HITM = 6
MS_EVT_REMOTE_DRAM = 7

DEFAULT_SAMPLE_PERIOD = 200_000


def _cache_config(cache_id: int, op_id: int, result_id: int) -> int:
    return cache_id | (op_id << 8) | (result_id << 16)


@dataclass(frozen=True)
class PmuAlias:
    perf_type: int
    config: int
    sample_period: int = DEFAULT_SAMPLE_PERIOD
    precise: bool = True
    logical: Optional[int] = None


_ALIAS_TABLE: Dict[str, PmuAlias] = {
    "cycles": PmuAlias(
        perf_type=PERF_TYPE_HARDWARE,
        config=PERF_COUNT_HW_CPU_CYCLES,
        sample_period=200_000,
        precise=False,
    ),
    "cpu-cycles": PmuAlias(
        perf_type=PERF_TYPE_HARDWARE,
        config=PERF_COUNT_HW_CPU_CYCLES,
        sample_period=200_000,
        precise=False,
    ),
    "llc-load-misses": PmuAlias(
        perf_type=PERF_TYPE_HW_CACHE,
        config=_cache_config(
            PERF_COUNT_HW_CACHE_LL,
            PERF_COUNT_HW_CACHE_OP_READ,
            PERF_COUNT_HW_CACHE_RESULT_MISS,
        ),
        sample_period=150_000,
        precise=True,
        logical=MS_EVT_L3_MISS,
    ),
    "mem_load_retired.l3_miss": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x20D1,
        sample_period=120_000,
        precise=True,
        logical=MS_EVT_L3_MISS,
    ),
    "br_misp_retired.all_branches": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x00C5,
        sample_period=100_000,
        precise=True,
        logical=MS_EVT_BRANCH_MISPRED,
    ),
    "br-misp-retired.all-branches": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x00C5,
        sample_period=100_000,
        precise=True,
        logical=MS_EVT_BRANCH_MISPRED,
    ),
    "br-misp-red.all-branches": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x00C5,
        sample_period=100_000,
        precise=True,
        logical=MS_EVT_BRANCH_MISPRED,
    ),
    "offcore_response.all_rfo": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x01B7,
        sample_period=80_000,
        precise=True,
        logical=MS_EVT_XSNP_HITM,
    ),
    "offcore_response.demand_rfo.hitm": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x01B7,
        sample_period=80_000,
        precise=True,
        logical=MS_EVT_XSNP_HITM,
    ),
    "offcore_response.all_requests": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x01B7,
        sample_period=120_000,
        precise=True,
        logical=MS_EVT_REMOTE_DRAM,
    ),
    "mem_load_retired.l3_miss.local": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x10D1,
        sample_period=120_000,
        precise=True,
        logical=MS_EVT_L3_MISS,
    ),
    "mem_load_retired.l3_miss.remote": PmuAlias(
        perf_type=PERF_TYPE_RAW,
        config=0x30D1,
        sample_period=120_000,
        precise=True,
        logical=MS_EVT_REMOTE_DRAM,
    ),
    "branches-misses": PmuAlias(
        perf_type=PERF_TYPE_HARDWARE,
        config=PERF_COUNT_HW_BRANCH_MISSES,
        sample_period=120_000,
        precise=True,
        logical=MS_EVT_BRANCH_MISPRED,
    ),
}


def _canonicalize(name: str) -> str:
    return name.strip().lower().replace(" ", "")


def build_pmu_update(event_names: List[str]) -> Tuple[Optional[Dict[str, object]], List[str]]:
    """Return a control-plane payload (and warnings) for the requested events."""

    warnings: List[str] = []
    events: List[Dict[str, object]] = []
    for raw_name in event_names:
        if not raw_name:
            continue
        key = _canonicalize(str(raw_name))
        alias = _ALIAS_TABLE.get(key)
        if not alias:
            warnings.append(f"unknown PMU alias '{raw_name}', skipping")
            continue
        desc: Dict[str, object] = {
            "name": raw_name,
            "type": alias.perf_type,
            "config": alias.config,
            "sample_period": alias.sample_period,
            "precise": alias.precise,
        }
        if alias.logical:
            desc["logical"] = alias.logical
        events.append(desc)
    if not events:
        return None, warnings
    group = {"name": "suite-override", "events": events}
    payload = {"sentinel": [group], "diagnostic": [group]}
    return payload, warnings
