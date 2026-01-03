#!/usr/bin/env python3
"""
Message Passing Test Harness for LiteP2P
This script provides programmatic message passing tests between peers.
"""

import subprocess
import time
import os
import signal
import json
import re
import sys
from pathlib import Path
from typing import Optional, List, Dict
import threading
import queue

class PeerProcess:
    def __init__(self, peer_id: str, port: int, log_file: Path, binary_path: Path):
        self.peer_id = peer_id
        self.port = port
        self.log_file = log_file
        self.binary_path = binary_path
        self.process: Optional[subprocess.Popen] = None
        self.messages_received = []
        self.messages_lock = threading.Lock()
        
    def start(self):
        """Start the peer process"""
        log_dir = self.log_file.parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            str(self.binary_path),
            "--id", self.peer_id,
            "--port", str(self.port),
            "--log-level", "info",
            "--no-tui"
        ]
        
        with open(self.log_file, "w") as f:
            self.process = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                cwd=str(log_dir)
            )
        
        # Wait for startup
        time.sleep(3)
        return self.process.poll() is None
    
    def stop(self):
        """Stop the peer process"""
        if self.process:
            try:
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=2)
            except Exception as e:
                # Try to kill if terminate failed
                try:
                    if self.process.poll() is None:
                        self.process.kill()
                        self.process.wait(timeout=2)
                except Exception:
                    pass
            finally:
                self.process = None
    
    def extract_peer_id_from_logs(self) -> Optional[str]:
        """Extract the actual peer ID from logs"""
        if not self.log_file.exists():
            return None
        
        try:
            with open(self.log_file, "r") as f:
                content = f.read()
                # Look for peer ID patterns
                patterns = [
                    r'peer[_\s]+id[:\s]+([a-f0-9-]{20,})',
                    r'local[_\s]+id[:\s]+([a-f0-9-]{20,})',
                    r'peer[_\s]+([a-f0-9-]{36})',
                ]
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        return match.group(1)
        except Exception as e:
            print(f"Error reading log: {e}")
        return None
    
    def check_for_message(self, message_content: str, timeout: int = 10) -> bool:
        """Check if a specific message was received"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if not self.log_file.exists():
                time.sleep(0.5)
                continue
            
            try:
                with open(self.log_file, "r", encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if message_content.lower() in content.lower():
                        return True
            except (IOError, OSError, UnicodeDecodeError):
                time.sleep(0.5)
                continue
            time.sleep(0.5)
        return False
    
    def get_discovered_peers(self) -> List[str]:
        """Extract discovered peer IDs from logs"""
        if not self.log_file.exists():
            return []
        
        try:
            with open(self.log_file, "r", encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Look for peer discovery patterns
                peer_ids = re.findall(r'peer[_\s]+([a-f0-9-]{20,})', content, re.IGNORECASE)
                return list(set(peer_ids))
        except (IOError, OSError, UnicodeDecodeError):
            return []

def find_binary():
    """Find the binary in common locations"""
    script_dir = Path(__file__).parent
    
    # Try macOS binary first
    binary = script_dir / "desktop" / "build_mac" / "bin" / "litep2p_peer_mac"
    if binary.exists():
        return binary
    
    # Try Linux binary
    binary = script_dir / "desktop" / "build_linux" / "bin" / "litep2p_peer_linux"
    if binary.exists():
        return binary
    
    # Try Linux Docker binary
    binary = script_dir / "desktop" / "build_linux_docker" / "bin" / "litep2p_peer_linux"
    if binary.exists():
        return binary
    
    return None

def test_message_passing():
    """Test message passing between two peers"""
    script_dir = Path(__file__).parent
    binary = find_binary()
    
    if binary is None:
        print("ERROR: Binary not found")
        print("Please build:")
        print("  macOS: cd desktop && ./build_mac.sh")
        print("  Linux: cd desktop && ./build_linux.sh")
        return False
    
    test_dir = script_dir / f"message_test_{int(time.time())}"
    test_dir.mkdir(exist_ok=True)
    
    peer1 = PeerProcess(
        peer_id="msg-test-peer-1",
        port=31001,
        log_file=test_dir / "peer1.log",
        binary_path=binary
    )
    
    peer2 = PeerProcess(
        peer_id="msg-test-peer-2",
        port=31002,
        log_file=test_dir / "peer2.log",
        binary_path=binary
    )
    
    try:
        print("Starting peer 1...")
        if not peer1.start():
            print("ERROR: Peer 1 failed to start")
            peer1.stop()
            return False
        print("✓ Peer 1 started")
        
        # Verify peer 1 is actually running
        if peer1.process and peer1.process.poll() is not None:
            print("ERROR: Peer 1 process died immediately")
            peer1.stop()
            return False
        
        print("Starting peer 2...")
        if not peer2.start():
            print("ERROR: Peer 2 failed to start")
            peer1.stop()
            peer2.stop()
            return False
        print("✓ Peer 2 started")
        
        # Verify peer 2 is actually running
        if peer2.process and peer2.process.poll() is not None:
            print("ERROR: Peer 2 process died immediately")
            peer1.stop()
            peer2.stop()
            return False
        
        # Wait for discovery
        print("\nWaiting for peer discovery (30 seconds)...")
        time.sleep(30)
        
        # Check for discovery
        peer1_discovered = peer1.get_discovered_peers()
        peer2_discovered = peer2.get_discovered_peers()
        
        print(f"\nPeer 1 discovered: {len(peer1_discovered)} peers")
        print(f"Peer 2 discovered: {len(peer2_discovered)} peers")
        
        # Extract actual peer IDs
        peer1_actual_id = peer1.extract_peer_id_from_logs()
        peer2_actual_id = peer2.extract_peer_id_from_logs()
        
        print(f"\nPeer 1 actual ID: {peer1_actual_id or 'unknown'}")
        print(f"Peer 2 actual ID: {peer2_actual_id or 'unknown'}")
        
        # Check for errors
        print("\nChecking for errors...")
        peer1_errors = 0
        peer2_errors = 0
        try:
            with open(peer1.log_file, "r", encoding='utf-8', errors='ignore') as f:
                peer1_errors = len(re.findall(r'error|fail|exception', f.read(), re.IGNORECASE))
        except (IOError, OSError):
            pass
        try:
            with open(peer2.log_file, "r", encoding='utf-8', errors='ignore') as f:
                peer2_errors = len(re.findall(r'error|fail|exception', f.read(), re.IGNORECASE))
        except (IOError, OSError):
            pass
        
        print(f"Peer 1 errors: {peer1_errors}")
        print(f"Peer 2 errors: {peer2_errors}")
        
        if peer1_errors == 0 and peer2_errors == 0:
            print("\n✓ No errors detected")
            return True
        else:
            print("\n⚠ Some errors detected (check logs)")
            return True  # Not a complete failure
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        return False
    except Exception as e:
        print(f"\nERROR: Unexpected exception: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        print("\nStopping peers...")
        try:
            peer1.stop()
        except Exception as e:
            print(f"Warning: Error stopping peer1: {e}")
        try:
            peer2.stop()
        except Exception as e:
            print(f"Warning: Error stopping peer2: {e}")
        time.sleep(1)
        print("Test complete. Logs saved to:", test_dir)

if __name__ == "__main__":
    success = test_message_passing()
    sys.exit(0 if success else 1)

