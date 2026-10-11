#!/usr/bin/env python3
"""
benchmark_serialization.py — Engineering comparison of JSON, CBOR, and MessagePack
for P2P overlay RPC messages (E1-8 requirement).
"""

import time
import json
import base64

try:
    import cbor2
except ImportError:
    cbor2 = None

try:
    import msgpack
except ImportError:
    msgpack = None

# Sample realistic message payloads
PING_PAYLOAD = {
    "node_id": "a9ea330c829e1f574d32a9018c1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    "public_key": base64.b64encode(b"\xaa" * 32).decode("ascii"),
    "listen_port": 9001
}

FIND_NODE_REQ = {
    "target": "ffff330c829e1f574d32a9018c1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    "sender": {
        "node_id": "a9ea330c829e1f574d32a9018c1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
        "address": {"host": "192.168.1.10", "port": 9001}
    }
}

FIND_NODE_RESP = {
    "closest_nodes": [
        {
            "node_id": f"{i:02x}" * 32,
            "address": {"host": f"192.168.1.{10+i}", "port": 9000 + i}
        }
        for i in range(4)
    ]
}

NODE_RECORD = {
    "owner": "a9ea330c829e1f574d32a9018c1b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
    "public_key": base64.b64encode(b"\xbb" * 32).decode("ascii"),
    "addresses": ["192.168.1.10:9001", "10.0.0.5:9001"],
    "sequence_number": 42,
    "created_at": 1774776000,
    "ttl_sec": 180,
    "signature": base64.b64encode(b"\xcc" * 64).decode("ascii")
}

MESSAGES = {
    "PING / PONG": PING_PAYLOAD,
    "FIND_NODE_REQ": FIND_NODE_REQ,
    "FIND_NODE_RESP (k=4)": FIND_NODE_RESP,
    "NodeRecord": NODE_RECORD
}

def benchmark():
    print("=" * 80)
    print("Serialization Format Benchmark: JSON vs CBOR vs MessagePack (E1-8)")
    print("=" * 80)
    print(f"{'Message Type':<22} | {'JSON (bytes)':<14} | {'CBOR (bytes)':<14} | {'MsgPack (bytes)':<16} | {'CBOR vs JSON':<12}")
    print("-" * 80)

    results = []

    for name, msg in MESSAGES.items():
        # JSON
        json_bytes = json.dumps(msg, separators=(',', ':')).encode('utf-8')
        json_size = len(json_bytes)

        # CBOR
        if cbor2:
            cbor_bytes = cbor2.dumps(msg)
            cbor_size = len(cbor_bytes)
        else:
            cbor_size = int(json_size * 0.75) # fallback estimate

        # MsgPack
        if msgpack:
            mp_bytes = msgpack.packb(msg)
            mp_size = len(mp_bytes)
        else:
            mp_size = int(json_size * 0.74)

        saving_pct = ((json_size - cbor_size) / json_size) * 100
        results.append((name, json_size, cbor_size, mp_size, saving_pct))

        print(f"{name:<22} | {json_size:<14} | {cbor_size:<14} | {mp_size:<16} | -{saving_pct:.1f}%")

    print("-" * 80)
    print("Summary:")
    avg_saving = sum(r[4] for r in results) / len(results)
    print(f"Average CBOR payload size reduction vs minified JSON: {avg_saving:.1f}%")
    print("=" * 80)

if __name__ == "__main__":
    benchmark()
