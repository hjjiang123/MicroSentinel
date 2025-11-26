-- Migration: add flow direction column support and ms_data_objects catalog
-- Run each statement sequentially in a ClickHouse client connected to the telemetry cluster.

-- 1. Add direction to raw samples so existing rows default to ingress (0).
ALTER TABLE ms_raw_samples
    ADD COLUMN IF NOT EXISTS direction UInt8 DEFAULT 0 AFTER ifindex;

-- 2. Add direction to flow rollups for directional aggregates.
ALTER TABLE ms_flow_rollup
    ADD COLUMN IF NOT EXISTS direction UInt8 DEFAULT 0 AFTER numa_node;

-- 3. Create the data object catalog used by automatic region registration.
CREATE TABLE IF NOT EXISTS ms_data_objects (
    object_id   UInt64,
    host        String,
    mapping     String,
    base        UInt64,
    size        UInt64,
    permissions String
) ENGINE = ReplacingMergeTree
ORDER BY (host, object_id);
