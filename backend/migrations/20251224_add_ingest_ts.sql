-- Add an explicit real-world (wall clock) ingestion timestamp for correlation.
-- This keeps existing event/bucket timestamps intact while enabling time-range queries.

ALTER TABLE ms_raw_samples
    ADD COLUMN IF NOT EXISTS ingest_ts DateTime64(9) DEFAULT now64(9) CODEC(Delta, ZSTD(3)) AFTER ts;

ALTER TABLE ms_flow_rollup
    ADD COLUMN IF NOT EXISTS ingest_ts DateTime64(9) DEFAULT now64(9) CODEC(Delta, ZSTD(3)) AFTER window_start;
