import unittest
import time
import requests
import json
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from src.onion_directory import OnionDirectory
from src.onion_directory_server import app

class MockRelay:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        
    
        self.long_term_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.long_term_public_key = self.long_term_private_key.public_key()
        
        
        self.onion_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.onion_public_key = self.onion_private_key.public_key()
    
    def get_public_keys_pem(self):
        """Get PEM-encoded public keys"""
        long_term_pem = self.long_term_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        onion_pem = self.onion_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return long_term_pem, onion_pem
    
    def sign_message(self, message: bytes) -> bytes:
        """Sign a message using the long-term private key"""
        return self.long_term_private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def upload_state(self, directory_url: str) -> requests.Response:
        """Upload relay state to directory"""
        long_term_pem, onion_pem = self.get_public_keys_pem()
        
        
        message = f"{self.ip}{self.port}{onion_pem}".encode()
        signature = self.sign_message(message)
        
        data = {
            "ip": self.ip,
            "port": self.port,
            "onion_key": onion_pem,
            "long_term_key": long_term_pem,
            "signature": signature.hex()
        }
        
        return requests.post(f"{directory_url}/upload_state", json=data)
    
    def send_heartbeat(self, directory_url: str) -> requests.Response:
        """Send heartbeat to directory"""
        message = f"{self.ip}{self.port}{time.time()}".encode()
        signature = self.sign_message(message)
        
        data = {
            "ip": self.ip,
            "port": self.port,
            "signature": signature.hex()
        }
        
        return requests.post(f"{directory_url}/heartbeat", json=data)

def run_test_server():
    """Run the directory server in a separate thread"""
    app.run(host='127.0.0.1', port=5000)

if __name__ == "__main__":
    # Start the directory server in a separate thread
    server_thread = threading.Thread(target=run_test_server)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(1)  # Give the server time to start
    
    
    try:
        print("Starting directory server testing...")
        directory_url = "http://127.0.0.1:5000"
        
        
        relay = MockRelay("127.0.0.1", 8000)
        print("\n1. Testing relay state upload...")
        response = relay.upload_state(directory_url)
        print(f"Upload response: {response.status_code} - {response.json()}")
        
        print("\n2. Testing heartbeat...")
        response = relay.send_heartbeat(directory_url)
        print(f"Heartbeat response: {response.status_code} - {response.json()}")
        
        print("\n3. Testing state download...")
        response = requests.get(f"{directory_url}/download_states")
        print(f"Download response: {response.status_code}")
        print("Current relay states:", json.dumps(response.json(), indent=2))
        
        print("\n4. Testing heartbeat timeout...")
        print("Waiting for heartbeat timeout (this will take 30 seconds)...")
        time.sleep(35) 
        response = requests.get(f"{directory_url}/download_states")
        print("Relay states after timeout:", json.dumps(response.json(), indent=2))
        
    except Exception as e:
        print(f"Error during testing: {e}")
    
    print("\nTesting completed!")