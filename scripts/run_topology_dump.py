#!/usr/bin/env python3
"""
scripts/run_topology_dump.py — Automated Star and Ring bootstrap topology runner (E2-7, E2-8).
Runs 5-node topologies, allows DHT convergence, and dumps routing tables to:
  results/star/node0.json ... node4.json
  results/ring/node0.json ... node4.json
"""

import os
import subprocess
import time
import sys
import json

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def run_topology(name, config_dir, port_base):
    print(f"\n{'='*70}\n[*] Running {name.upper()} bootstrap topology...\n{'='*70}")
    out_dir = os.path.join("results", name)
    os.makedirs(out_dir, exist_ok=True)

    net_name = f"p2p_{name}_net"
    run_cmd(f"docker network create {net_name}")
    for i in range(5):
        run_cmd(f"docker rm -f p2p_{name}_node{i}")

    # Build base args
    nodes = []
    # Node 0 (Root/First node)
    cmd0 = [
        "docker", "run", "--rm",
        "--name", f"p2p_{name}_node0",
        "--network", net_name,
        "p2p-test",
        "/app/build/p2p_node",
        "--config", f"/app/config/{name}/node0.toml",
        "--port", str(port_base),
        "--dump-routing", "-",
        "--duration", "10",
        "--log-level", "info"
    ]
    p0 = subprocess.Popen(cmd0, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    nodes.append(p0)
    time.sleep(1)

    # Nodes 1..4
    for i in range(1, 5):
        boot_target = f"p2p_{name}_node0:{port_base}" if name == "star" else f"p2p_{name}_node{i-1}:{port_base + i - 1}"
        cmd_i = [
            "docker", "run", "--rm",
            "--name", f"p2p_{name}_node{i}",
            "--network", net_name,
            "p2p-test",
            "/app/build/p2p_node",
            "--config", f"/app/config/{name}/node{i}.toml",
            "--port", str(port_base + i),
            "--bootstrap", boot_target,
            "--dump-routing", "-",
            "--duration", "10",
            "--log-level", "info"
        ]
        pi = subprocess.Popen(cmd_i, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        nodes.append(pi)
        time.sleep(0.5)

    print(f"[*] All 5 {name} nodes running. Waiting 10s for DHT convergence and automatic routing dump...")
    dumped = 0
    for idx, p in enumerate(nodes):
        out, _ = p.communicate()
        # Extract JSON from output
        start_tag = "--- ROUTING_TABLE_JSON_START ---"
        end_tag = "--- ROUTING_TABLE_JSON_END ---"
        if start_tag in out and end_tag in out:
            json_str = out.split(start_tag)[1].split(end_tag)[0].strip()
            path = os.path.join(out_dir, f"node{idx}.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write(json_str)
            try:
                data = json.loads(json_str)
                count = sum(len(b.get("contacts", [])) for b in data.get("buckets", [])) if "buckets" in data else 0
                print(f"  [+] {name.capitalize()} node{idx}: {path} ({count} contacts in routing table)")
                dumped += 1
            except Exception as e:
                print(f"  [!] {name} node{idx} JSON saved but failed to parse: {e}")
        else:
            print(f"  [-] {name} node{idx} did not output routing dump. Output:\n{out[-400:]}")

    run_cmd(f"docker network rm {net_name}")
    print(f"[+] Total {name} dumps saved: {dumped}/5")
    return dumped == 5

def main():
    os.makedirs("results/star", exist_ok=True)
    os.makedirs("results/ring", exist_ok=True)

    star_ok = run_topology("star", "config/star", 9000)
    ring_ok = run_topology("ring", "config/ring", 9020)

    if star_ok and ring_ok:
        print("\n[SUCCESS] Both Star and Ring topologies converged and routing tables dumped successfully.")
        return 0
    else:
        print("\n[WARNING] Some dumps were missing. Check container output.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
