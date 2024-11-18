# the code for the database holding the relays and their symmetric keys

import time
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

# class CircuitNode:
#     def __init__(self, node_ip, node_key):
#         self.node_ip = node_ip
#         self.node_key = node_key
        
# # retrieve a circuit list comprised of CircuitNodes
# def fetch_circuit(src_ip, dest_ip):
#     first_node = CircuitNode(src_ip, os.urandom(32))
#     last_node = CircuitNode(dest_ip, os.urandom(32))
#     return [first_node, last_node]

@dataclass
class RelayState:
    onion_key: str  # Public onion key in PEM format
    ip: str
    port: int
    last_heartbeat: float
    long_term_key: str  # Long-term public key in PEM format

class DirectoryServer:
    def __init__(self, heartbeat_timeout: int = 30):
        self.relays: Dict[str, RelayState] = {}  # ip:port -> RelayState
        self.heartbeat_timeout = heartbeat_timeout
        self.lock = threading.Lock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_dead_relays, daemon=True)
        self.cleanup_thread.start()

    def _cleanup_dead_relays(self):
        """Remove relays that haven't sent a heartbeat within the timeout period"""
        while True:
            current_time = time.time()
            with self.lock:
                dead_relays = [
                    relay_id for relay_id, state in self.relays.items()
                    if current_time - state.last_heartbeat > self.heartbeat_timeout
                ]
                for relay_id in dead_relays:
                    print(f"Removing dead relay: {relay_id}")
                    del self.relays[relay_id]
            time.sleep(5)

    def verify_signature(self, message: bytes, signature: bytes, public_key: str) -> bool:
        """Verify the signature of a message using the relay's long-term public key"""
        try:
            key = serialization.load_pem_public_key(public_key.encode())
            key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def update_relay_state(self, ip: str, port: int, onion_key: str, 
                          long_term_key: str, signature: bytes) -> bool:
        """Update or add a relay's state"""
        relay_id = f"{ip}:{port}"
        
        # Verify signature
        message = f"{ip}{port}{onion_key}".encode()
        if not self.verify_signature(message, signature, long_term_key):
            return False

        with self.lock:
            self.relays[relay_id] = RelayState(
                onion_key=onion_key,
                ip=ip,
                port=port,
                last_heartbeat=time.time(),
                long_term_key=long_term_key
            )
        return True

    def update_heartbeat(self, ip: str, port: int, signature: bytes) -> bool:
        """Update the heartbeat timestamp for a relay"""
        relay_id = f"{ip}:{port}"
        
        with self.lock:
            if relay_id not in self.relays:
                return False
            
            # Verify signature
            message = f"{ip}{port}{time.time()}".encode()
            if not self.verify_signature(message, signature, self.relays[relay_id].long_term_key):
                return False
                
            self.relays[relay_id].last_heartbeat = time.time()
            return True

    def get_relay_states(self) -> List[dict]:
        """Get all active relay states"""
        with self.lock:
            return [
                {
                    "ip": state.ip,
                    "port": state.port,
                    "onion_key": state.onion_key,
                    "long_term_key": state.long_term_key
                }
                for state in self.relays.values()
            ]