#!/usr/bin/env python3

import subprocess
import time
import re
import requests
import json
import os
import signal
import sys

AGENT_BIN = "agent/build/micro_sentinel_agent"
AGENT_CONF = "agent/agent.conf"
SERVER_BIN = "experiments/workloads/lb/lb_hot_server_5.3_v1"
CLIENT_SCRIPT = "experiments/workloads/lb/data_object_client.py"

CONTROL_URL = "http://127.0.0.1:9201"

def run_experiment():
    print("[*] Starting MicroSentinel Agent...")
    agent_proc = subprocess.Popen(
        ["sudo", AGENT_BIN, f"--config={AGENT_CONF}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for agent to be ready
    time.sleep(2)
    
    print("[*] Starting Server...")
    server_proc = subprocess.Popen(
        [SERVER_BIN, "--host", "0.0.0.0", "--port", "7100", "--workers", "4", "--payload-bytes", "512", "--stride-bytes", "256", "--rounds", "1000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

    objects = []
    server_pid = server_proc.pid
    print(f"[*] Server PID: {server_pid}")

    # Read server output to find data layout
    # We need to read line by line without blocking forever
    
    print("[*] Waiting for data layout...")
    layout_regex = re.compile(r"\[data_layout\] object=(\w+) type=(\w+) start=(0x[0-9a-f]+) end=(0x[0-9a-f]+) size=(\d+)")
    
    found_objects = 0
    while found_objects < 4:
        line = server_proc.stdout.readline()
        if not line:
            break
        print(f"[Server] {line.strip()}")
        match = layout_regex.search(line)
        if match:
            obj_name = match.group(1)
            obj_type = match.group(2)
            start_addr = int(match.group(3), 16)
            size = int(match.group(5))
            
            objects.append({
                "pid": server_pid,
                "address": start_addr,
                "name": obj_name,
                "type": obj_type,
                "size": size
            })
            found_objects += 1

    print(f"[*] Found {len(objects)} objects. Registering with Agent...")
    
    for obj in objects:
        try:
            resp = requests.post(f"{CONTROL_URL}/api/v1/symbols/data", json=obj)
            if resp.status_code == 200:
                print(f"    Registered {obj['name']} @ {hex(obj['address'])}")
            else:
                print(f"    Failed to register {obj['name']}: {resp.text}")
        except Exception as e:
            print(f"    Error registering {obj['name']}: {e}")

    # Configure Token Bucket / PMU if needed
    # For this experiment, we want L3 Misses
    pmu_config = {
        "events": ["MEM_LOAD_RETIRED.L3_MISS", "OFFCORE_RESPONSE.ALL_RFO"]
    }
    try:
        requests.post(f"{CONTROL_URL}/api/v1/pmu-config", json=pmu_config)
        print("[*] Configured PMU events")
    except Exception as e:
        print(f"[*] Failed to configure PMU: {e}")

    print("[*] Starting Client...")
    subprocess.run(
        ["python3", CLIENT_SCRIPT, "--host", "127.0.0.1", "--port", "7100", "--connections", "16", "--duration", "10"],
        check=True
    )
    
    print("[*] Client finished. Stopping Server and Agent...")
    server_proc.terminate()
    subprocess.run(["sudo", "kill", str(agent_proc.pid)])
    
    try:
        server_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server_proc.kill()
        
    analyze_results(objects)
    print("[*] Experiment Complete.")

def analyze_results(objects):
    print("[*] Analyzing results in ClickHouse...")
    # Wait a bit for data to flush
    time.sleep(2)
    
    # 1. Get Object IDs
    obj_map = {} # name -> id
    query_ids = "SELECT mapping, object_id FROM ms_data_objects WHERE mapping IN ('A', 'B', 'o1', 'o2') ORDER BY timestamp DESC LIMIT 4"
    # Note: timestamp column might not exist or be named differently, using simple deduplication logic if needed
    # Actually, let's just get all and pick the latest for each name if multiple exist, 
    # but since we just registered them, they should be there.
    # The previous check showed multiple entries. We need the ones matching our addresses.
    # Better: Get all entries and match by base address.
    
    try:
        resp = requests.get("http://localhost:8123/", params={"query": "SELECT mapping, base, object_id FROM ms_data_objects WHERE mapping IN ('A', 'B', 'o1', 'o2')"})
        if resp.status_code != 200:
            print(f"    [ERROR] Failed to fetch object IDs: {resp.text}")
            return

        # Parse DB objects
        db_objects = {} # (name, base) -> object_id
        for line in resp.text.strip().split('\n'):
            if not line: continue
            parts = line.split('\t')
            if len(parts) >= 3:
                name, base, oid = parts[0], int(parts[1]), int(parts[2])
                db_objects[(name, base)] = oid
        
        # Map current run's objects to IDs
        current_run_ids = {} # name -> object_id
        for obj in objects:
            key = (obj['name'], obj['address'])
            if key in db_objects:
                current_run_ids[obj['name']] = db_objects[key]
            else:
                print(f"    [WARNING] Object {obj['name']} @ {hex(obj['address'])} not found in DB")
        
        if len(current_run_ids) < 4:
            print("    [FAILURE] Could not resolve all object IDs. Aborting analysis.")
            return

        print(f"    Resolved Object IDs: {current_run_ids}")

        # 2. Fetch Samples
        # ms_raw_samples does not have data_object_id. We must use ms_flow_rollup for attribution check,
        # OR we must map raw samples to objects ourselves (which is what we want to verify Agent doing).
        # Wait, the goal is to verify MicroSentinel's attribution.
        # If ms_raw_samples doesn't have data_object_id, we can't verify per-sample attribution from it directly
        # unless we join with something or use ms_flow_rollup.
        # However, ms_flow_rollup aggregates by (flow, function, stack, event, object_id).
        # It does NOT have the raw data_addr.
        # So we have a dilemma:
        # - ms_raw_samples has addr but no object_id (in current schema).
        # - ms_flow_rollup has object_id but no addr.
        
        # BUT, the experiment design says: "Verify MicroSentinel can attribute...".
        # If the Agent is doing its job, ms_flow_rollup should show samples with the correct data_object_id.
        # But to calculate "Accuracy", we need to know the "Ground Truth" for those samples.
        # The Ground Truth is: "Flow X accesses Object Y".
        # So we can check: For Flow X, do the samples in ms_flow_rollup have data_object_id == Y?
        
        # Let's use ms_flow_rollup for "Data Object Attribution Accuracy".
        # And for "Cache Line Consistency", we really need raw addresses + object IDs.
        # Since ms_raw_samples lacks object_id, we cannot verify "Cache Line Consistency" as defined 
        # (same cache line -> same object) using only DB output if the DB doesn't store that link per sample.
        # UNLESS we assume the Agent's internal logic is what we are testing, and we trust the Agent's output.
        
        # Actually, looking at the C++ code (clickhouse_sink.cpp), ms_raw_samples insertion DOES NOT include data_object_id.
        # It only includes: ts, ingest_ts, host, cpu, pid, tid, flow_id, pmu_event, ip, data_addr, ...
        
        # So we can only verify "Data Object Attribution Accuracy" via Flow-to-Object mapping in ms_flow_rollup.
        # We know:
        # Tag 0 -> Object A
        # Tag 1 -> Object B
        # Tag 2 -> Object o1
        # Tag 3 -> Object o2
        # And the client distributes tags: connection i -> tag (i % 4).
        # But we don't easily know which Flow ID corresponds to which connection/tag without more instrumentation.
        
        # Alternative: The server code touches memory.
        # We can look at ms_raw_samples to see the addresses.
        # We can manually map these addresses to objects (using our known layout).
        # Then we can check if ms_flow_rollup has corresponding counts for those objects.
        # But ms_flow_rollup aggregates over time.
        
        # Let's adjust the strategy.
        # We will calculate "Data Object Attribution Accuracy" by:
        # 1. Summing 'samples' in ms_flow_rollup for each data_object_id.
        # 2. Comparing this with the expected distribution or just checking if the right objects are present.
        # But the metric is "Accuracy".
        # If we can't link specific samples to objects in the DB, we can't strictly calculate "Accuracy" 
        # unless we rely on the Flow ID.
        
        # Let's try to map Flow ID to Object.
        # The client runs 16 connections.
        # We can't easily know the Flow ID for each connection unless we trace it.
        
        # Wait, the user prompt asks to calculate "Cache Line Consistency".
        # If the DB schema doesn't support it, maybe I should mention that or try to find a workaround.
        # Workaround: The Agent *internally* does the mapping.
        # If we want to verify it, we might need to enable a debug mode or check if I missed a column.
        # I checked ms_raw_samples and it indeed lacks data_object_id.
        
        # However, the `docs/exp_design.md` says:
        # "3. 对所有采样的 addr，确定其所属对象，统计... 对应 cache line 编号"
        # This implies we might need to do this analysis *offline* using raw samples and the known map,
        # OR the design assumes ms_raw_samples *has* the object ID (which it currently doesn't).
        
        # Let's implement what we CAN do:
        # 1. "Data Object Attribution Accuracy":
        #    We can fetch raw samples (addr) and manually map them to objects (Ground Truth).
        #    Then we fetch aggregated samples (object_id) from ms_flow_rollup.
        #    We can compare the TOTAL counts. 
        #    e.g. Raw samples in A's range = 100. Aggregated samples for A = 95.
        #    Accuracy ~ 95%. (This assumes no other flows touch A, which is true here).
        
        # 2. "Cache Line Consistency":
        #    Since we don't have (addr, object_id) pairs, we can't verify this from DB outputs.
        #    We can only verify that the Agent *registered* the objects correctly.
        #    I will print a warning about this limitation.
        
        print("    [INFO] ms_raw_samples lacks data_object_id. Using aggregate counts from ms_flow_rollup.")
        
        # Fetch raw sample counts per object (Ground Truth)
        raw_counts = {name: 0 for name in current_run_ids.keys()}
        query_raw = "SELECT data_addr FROM ms_raw_samples WHERE ts > now() - INTERVAL 30 SECOND AND data_addr != 0"
        resp = requests.get("http://localhost:8123/", params={"query": query_raw})
        if resp.status_code == 200:
            for line in resp.text.strip().split('\n'):
                if not line: continue
                addr = int(line)
                for obj in objects:
                    if obj['address'] <= addr < (obj['address'] + obj['size']):
                        raw_counts[obj['name']] += 1
                        break
        
        print(f"    Ground Truth Samples (from Raw Addrs): {raw_counts}")
        
        # Fetch attributed counts from Rollup
        attributed_counts = {name: 0 for name in current_run_ids.keys()}
        query_rollup = "SELECT data_object_id, sum(samples) FROM ms_flow_rollup WHERE window_start > now() - INTERVAL 30 SECOND GROUP BY data_object_id"
        resp = requests.get("http://localhost:8123/", params={"query": query_rollup})
        if resp.status_code == 200:
            rollup_map = {}
            for line in resp.text.strip().split('\n'):
                if not line: continue
                parts = line.split('\t')
                rollup_map[int(parts[0])] = int(parts[1])
            
            for name, oid in current_run_ids.items():
                attributed_counts[name] = rollup_map.get(oid, 0)
                
        print(f"    Attributed Samples (from Rollup): {attributed_counts}")
        
        # Calculate Accuracy
        total_raw = sum(raw_counts.values())
        total_attr = sum(attributed_counts.values())
        
        if total_raw > 0:
            # We cap attribution at raw count to avoid >100% due to timing skew
            matched = 0
            for name in raw_counts:
                matched += min(raw_counts[name], attributed_counts[name])
            
            accuracy = (matched / total_raw) * 100.0
            print(f"    [METRIC] Data Object Attribution Accuracy (Approx): {accuracy:.2f}%")
        else:
            print("    [METRIC] Data Object Attribution Accuracy: N/A (No raw samples)")

        print("    [METRIC] Cache Line Consistency: N/A (Requires data_object_id in ms_raw_samples)")

    except Exception as e:
        print(f"    [ERROR] Analysis failed: {e}")

if __name__ == "__main__":
    try:
        run_experiment()
    except KeyboardInterrupt:
        print("\nInterrupted.")
