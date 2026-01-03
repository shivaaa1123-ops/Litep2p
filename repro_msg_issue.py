import subprocess
import time
import os
import shutil
import sys
import threading

# Paths
BIN_PATH = os.path.abspath("desktop/build_mac/bin/litep2p_peer_mac")
WORK_DIR = os.path.abspath("repro_work_dir")

PEER_A_ID = "11111111-1111-1111-1111-111111111111"
PEER_B_ID = "22222222-2222-2222-2222-222222222222"

def setup_dir(name):
    path = os.path.join(WORK_DIR, name)
    if os.path.exists(path):
        shutil.rmtree(path)
    # Create a nested working directory so the relative LocalPeerDb path
    # "../../litep2p_peers.sqlite" resolves to a per-peer location (avoids
    # two peers fighting over the same DB file).
    nested_cwd = os.path.join(path, "wd", "run")
    os.makedirs(nested_cwd)
    return nested_cwd

def run_peer(name, port, peer_id, cwd):
    cmd = [BIN_PATH, "--port", str(port), "--id", peer_id, "--no-tui"]
    print(f"[{name}] Starting: {' '.join(cmd)}")
    # Open with pipes for stdin/stdout
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1  # Line buffered
    )
    return proc

def read_output(name, proc, stop_event, logs):
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            break
        line = line.strip()
        if line:
            logs.append(f"[{name}] {line}")
            # print(f"[{name}] {line}") # Optional: print real-time

import json

def get_keystore_path(dir_path):
    return os.path.join(dir_path, "keystore", "noise_keystore.json")

def read_keystore(dir_path):
    path = get_keystore_path(dir_path)
    if not os.path.exists(path):
        return None
    with open(path, 'r') as f:
        return json.load(f)

def write_keystore(dir_path, data):
    path = get_keystore_path(dir_path)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def main():
    if not os.path.exists(BIN_PATH):
        print(f"Error: Binary not found at {BIN_PATH}")
        return

    print("--- Setting up reproduction environment ---")
    subprocess.run(["pkill", "-f", "litep2p_peer_mac"], stderr=subprocess.DEVNULL)
    time.sleep(1)

    dir_a = setup_dir("peer_a")
    dir_b = setup_dir("peer_b")

    # Clean up per-peer LocalPeerDb files (cwd/../../litep2p_peers.sqlite)
    db_a = os.path.abspath(os.path.join(dir_a, "..", "..", "litep2p_peers.sqlite"))
    db_b = os.path.abspath(os.path.join(dir_b, "..", "..", "litep2p_peers.sqlite"))
    for db in {db_a, db_b}:
        if os.path.exists(db):
            print(f"Removing stale peer DB: {db}")
            os.remove(db)

    # Phase 1: Generate Keys
    print("--- Phase 1: Generating Keys ---")
    proc_a = run_peer("PeerA_Gen", 30011, PEER_A_ID, dir_a)
    proc_b = run_peer("PeerB_Gen", 30012, PEER_B_ID, dir_b)
    time.sleep(2)
    proc_a.terminate()
    proc_b.terminate()
    proc_a.wait()
    proc_b.wait()

    # Phase 2: Exchange Keys
    print("--- Phase 2: Exchanging Keys ---")
    ks_a = read_keystore(dir_a)
    ks_b = read_keystore(dir_b)

    if not ks_a or not ks_b:
        print("Error: Keystores not generated")
        return

    pk_a = ks_a['local_public_key_hex']
    pk_b = ks_b['local_public_key_hex']

    print(f"Peer A Public Key: {pk_a}")
    print(f"Peer B Public Key: {pk_b}")

    ks_a['peer_keys'][PEER_B_ID] = pk_b
    ks_b['peer_keys'][PEER_A_ID] = pk_a

    write_keystore(dir_a, ks_a)
    write_keystore(dir_b, ks_b)

    # Phase 3: Run Test
    print("--- Phase 3: Running Connection Test ---")
    stop_event = threading.Event()
    logs_a = []
    logs_b = []

    print("--- Starting Peer A ---")
    proc_a = run_peer("PeerA", 30011, PEER_A_ID, dir_a)
    t_a = threading.Thread(target=read_output, args=("PeerA", proc_a, stop_event, logs_a))
    t_a.start()

    print("--- Starting Peer B ---")
    proc_b = run_peer("PeerB", 30012, PEER_B_ID, dir_b)
    t_b = threading.Thread(target=read_output, args=("PeerB", proc_b, stop_event, logs_b))
    t_b.start()

    time.sleep(3) # Wait for startup

    print("--- Connecting A -> B ---")
    try:
        proc_a.stdin.write(f"connect {PEER_B_ID}\n")
        proc_a.stdin.flush()
    except Exception as e:
        print(f"Error writing to Peer A: {e}")

    # Wait for handshake to complete (or timeout)
    deadline = time.time() + 15
    while time.time() < deadline:
        handshake_a = any(("Noise handshake completed" in l) or ("Handshake complete" in l) for l in logs_a)
        handshake_b = any(("Noise handshake completed" in l) or ("Handshake complete" in l) for l in logs_b)
        if handshake_a and handshake_b:
            break
        time.sleep(0.25)

    print("--- Sending Message A -> B ---")
    try:
        proc_a.stdin.write(f"send {PEER_B_ID} HelloFromPeerA\n")
        proc_a.stdin.flush()
    except Exception as e:
        print(f"Error writing to Peer A: {e}")

    time.sleep(5) # Wait for delivery

    print("--- Stopping Peers ---")
    stop_event.set()
    proc_a.terminate()
    proc_b.terminate()
    t_a.join()
    t_b.join()

    print("\n--- Analysis ---")
    
    # Check for handshake success
    handshake_a = any(("Noise handshake completed" in l) or ("Handshake complete" in l) for l in logs_a)
    handshake_b = any(("Noise handshake completed" in l) or ("Handshake complete" in l) for l in logs_b)
    print(f"Handshake A: {handshake_a}")
    print(f"Handshake B: {handshake_b}")

    # Check for message receipt
    msg_received = any("HelloFromPeerA" in l for l in logs_b)
    print(f"Message Received by B: {msg_received}")

    print("\n--- Logs Peer A (Head) ---")
    for l in logs_a[:50]:
        print(l)

    print("\n--- Logs Peer A (Tail) ---")
    for l in logs_a[-20:]:
        print(l)

    print("\n--- Logs Peer B (Head) ---")
    for l in logs_b[:50]:
        print(l)

    print("\n--- Logs Peer B (Tail) ---")
    for l in logs_b[-20:]:
        print(l)

if __name__ == "__main__":
    main()
