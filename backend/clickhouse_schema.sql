-- Raw sample payload mirrors agent/src/clickhouse_sink.cpp JSONEachRow inserts.
-- norm_cost stores the per-sample normalized contribution derived from the rotating PMU scale.
CREATE TABLE IF NOT EXISTS ms_raw_samples (
    ts          DateTime64(9) CODEC(Delta, ZSTD(3)),
    ingest_ts   DateTime64(9) DEFAULT now64(9) CODEC(Delta, ZSTD(3)),
    host        String,
    cpu         UInt16,
    pid         UInt32,
    tid         UInt32,
    flow_id     UInt64,
    pmu_event   UInt32,
    ip          UInt64,
    data_addr   UInt64,
    lbr         Array(Tuple(UInt64, UInt64)),
    gso_segs    UInt32,
    ifindex     UInt16,
    direction   UInt8,
    numa_node   UInt16,
    l4_proto    UInt8,
    norm_cost   Float64
) ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (host, ts, cpu);

CREATE TABLE IF NOT EXISTS ms_flow_rollup (
    window_start DateTime64(9) CODEC(Delta, ZSTD(3)),
    ingest_ts    DateTime64(9) DEFAULT now64(9) CODEC(Delta, ZSTD(3)),
    host         String,
    flow_id      UInt64,
    function_id  UInt64,
    callstack_id UInt64,
    pmu_event    UInt32,
    numa_node    UInt16,
    direction    UInt8,
    interference_class UInt8,
    data_object_id UInt64,
    samples      UInt64,
    norm_cost    Float64
) ENGINE = SummingMergeTree
ORDER BY (host, window_start, flow_id, function_id, callstack_id, pmu_event, numa_node, data_object_id, interference_class);

CREATE TABLE IF NOT EXISTS ms_stack_traces (
    stack_id UInt64,
    host     String,
    frames   Array(Tuple(
        String, -- binary
        String, -- function
        String, -- file
        Int32   -- line
    ))
) ENGINE = ReplacingMergeTree
ORDER BY (host, stack_id);

CREATE TABLE IF NOT EXISTS ms_data_objects (
    object_id   UInt64,
    host        String,
    mapping     String,
    base        UInt64,
    size        UInt64,
    permissions String
) ENGINE = ReplacingMergeTree
ORDER BY (host, object_id);
