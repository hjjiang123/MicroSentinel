# Upgrade Guide: Flow Direction + Data Object Release

This guide documents how to roll out the direction-aware sample format and automatic data-object registration safely across a cluster.

## 1. Schedule maintenance window
- Coordinate with ClickHouse and agent owners; the `ms_sample` layout changed (new `direction` byte) and the backend introduces the `ms_data_objects` table.
- Expect a brief ingestion pause while agents restart. Query traffic can continue.

## 2. Apply ClickHouse migrations
1. Open a ClickHouse client connected to the telemetry cluster.
2. Run the statements in `backend/migrations/202501_direction_and_data_objects.sql`.
3. Validate the schema:
   ```sql
   DESCRIBE TABLE ms_raw_samples;
   DESCRIBE TABLE ms_flow_rollup;
   DESCRIBE TABLE ms_data_objects;
   ```
4. Confirm new columns default to `0` (ingress) for historical rows.

## 3. Rebuild and redeploy the eBPF collector
1. Rebuild the kernel objects to pick up the updated `ms_sample` structure:
   ```bash
   cd bpf
   make clean && make
   ```
2. Distribute the new `micro_sentinel_kern.bpf.o` artifact to hosts running the collector.
3. Reload the BPF program on each host (systemd unit: `systemctl restart micro-sentinel-bpf`).

## 4. Rebuild and redeploy the user-space agent
1. Rebuild the agent binaries from the repo root:
   ```bash
   cmake -S . -B build
   cmake --build build -j$(nproc)
   ctest --test-dir build --output-on-failure
   ```
2. Publish the new `micro_sentinel_agent` binary (e.g., package, container, or rsync).
3. Rolling restart the agent service:
   ```bash
   systemctl restart micro-sentinel-agent
   ```
4. Watch logs for schema or serialization warnings before proceeding to the next host.

## 5. Post-deployment checks
- Verify ClickHouse ingestion resumed (`SELECT count() FROM ms_raw_samples WHERE ts > now() - 300`).
- Ensure Prometheus metrics contain the new `direction` label (`micro_sentinel_flow_cost{direction="rx"}` etc.).
- On a sample host, use `bpftool map dump id <id>` to confirm `direction` values vary for TX vs RX flows.

## 6. Rollback plan
- If issues arise, revert to the previous agent/BPF build and keep the new columns/table (they are backward compatible).
- To fully roll back, drop the columns/table after stopping the upgraded agents, but this should rarely be necessary.
