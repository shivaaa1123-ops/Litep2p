import asyncio
import websockets
import json
import socket
import struct
import random
import argparse
import logging
import time

# Configuration – set via env vars, or fallback to placeholders
import os

SIGNALING_URL = os.environ.get("SIGNALING_URL", "ws://SIGNALING_SERVER_IP:8765")
TURN_IP = os.environ.get("TURN_IP", "TURN_SERVER_IP")
TURN_PORT = int(os.environ.get("TURN_PORT", "3478"))
TURN_USER = os.environ.get("TURN_USER", "litep2p")
TURN_PASS = os.environ.get("TURN_PASS", "TURN_PASSWORD")  # override via env
REALM = os.environ.get("TURN_REALM", "litep2p.org")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TurnClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 0))
        self.relayed_addr = None

    def create_stun_message(self, msg_type, attrs=[]):
        tid = [random.randint(0, 255) for _ in range(12)]
        msg = struct.pack('>H', msg_type) + struct.pack('>H', 0) + struct.pack('>I', 0x2112A442) + bytes(tid)
        
        attr_body = b''
        for t, v in attrs:
            attr_body += struct.pack('>H', t) + struct.pack('>H', len(v)) + v
            pad = (4 - (len(v) % 4)) % 4
            attr_body += b'\x00' * pad
            
        # Update length
        msg = msg[:2] + struct.pack('>H', len(attr_body)) + msg[4:] + attr_body
        return msg, bytes(tid)

    def allocate(self):
        logging.info(f"TURN: Allocating relay on {TURN_IP}:{TURN_PORT}...")
        
        # 1. Send Allocate Request (no auth)
        # Requested Transport: UDP (17) -> 0x11000000
        transport = struct.pack('BBBB', 17, 0, 0, 0)
        msg, tid = self.create_stun_message(0x0003, [(0x0019, transport)])
        self.sock.sendto(msg, (TURN_IP, TURN_PORT))
        
        # 2. Receive 401 Challenge
        data, _ = self.sock.recvfrom(2048)
        # Parse Realm and Nonce (Simplified parsing for test)
        # In a real script we'd parse TLVs properly. 
        # For this test, we assume the server works and we just need to prove connectivity.
        # Since implementing full STUN/TURN auth in a single script is complex, 
        # we will test the STUN Binding first (simpler) to prove reachability.
        
        logging.info("TURN: Server reachable. (Skipping full auth implementation in test script)")
        return True

    def close(self):
        self.sock.close()

async def run_peer(role, my_id, target_id):
    uri = SIGNALING_URL
    logging.info(f"Connecting to Signaling Server: {uri}")
    
    async with websockets.connect(uri) as websocket:
        # 1. Register
        await websocket.send(json.dumps({"type": "REGISTER", "peer_id": my_id}))
        resp = await websocket.recv()
        logging.info(f"Signaling: {resp}")

        # 2. Wait for peer
        if role == "responder":
            logging.info("Waiting for offer...")
            async for message in websocket:
                data = json.loads(message)
                if data.get('type') == 'SIGNAL':
                    payload = data.get('payload')
                    logging.info(f"Received Signal: {payload}")
                    
                    # Send Answer
                    await websocket.send(json.dumps({
                        "type": "SIGNAL", 
                        "target_peer_id": target_id, 
                        "payload": "HELLO_FROM_RESPONDER"
                    }))
                    break
        else:
            # Initiator
            logging.info("Sending Offer...")
            await asyncio.sleep(2) # Wait for responder to be ready
            await websocket.send(json.dumps({
                "type": "SIGNAL", 
                "target_peer_id": target_id, 
                "payload": "HELLO_FROM_INITIATOR"
            }))
            
            async for message in websocket:
                data = json.loads(message)
                if data.get('type') == 'SIGNAL':
                    logging.info(f"Received Answer: {data.get('payload')}")
                    break

        logging.info("Signaling Test: SUCCESS")
        
        # 3. Test TURN Reachability (UDP)
        logging.info("Testing TURN Server Reachability...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            # Send STUN Binding Request
            tid = [random.randint(0, 255) for _ in range(12)]
            msg = struct.pack('>H', 0x0001) + struct.pack('>H', 0) + struct.pack('>I', 0x2112A442) + bytes(tid)
            sock.sendto(msg, (TURN_IP, TURN_PORT))
            data, addr = sock.recvfrom(2048)
            logging.info(f"TURN Server replied from {addr}")
            logging.info("TURN Test: SUCCESS")
        except Exception as e:
            logging.error(f"TURN Test Failed: {e}")
        finally:
            sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["initiator", "responder"], required=True)
    args = parser.parse_args()
    
    my_id = "peer_A" if args.role == "initiator" else "peer_B"
    target_id = "peer_B" if args.role == "initiator" else "peer_A"
    
    try:
        asyncio.run(run_peer(args.role, my_id, target_id))
    except KeyboardInterrupt:
        pass
