import requests
import urllib3
import logging
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import time

# Disable warnings for self-signed certificates during testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TestRelay:
    def __init__(self, ip="192.168.1.100", port=9001):
        self.ip = ip
        self.port = port
        
        self.long_term_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        self.onion_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    def get_public_keys_pem(self):
        """Get PEM-encoded public keys"""
        long_term_pem = self.long_term_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        onion_pem = self.onion_private_key.public_key().public_bytes(
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

def test_server_endpoint(protocol, endpoint, data=None, method='GET'):
    """Test a specific endpoint with given protocol"""
    base_url = f"{protocol}://127.0.0.1:8001"
    url = f"{base_url}/{endpoint}"
    
    try:
        if method == 'GET':
            response = requests.get(url, verify=False)
        else:  # POST
            response = requests.post(url, json=data, verify=False)
        return response
    except requests.exceptions.SSLError as e:
        print(f"SSL Error with {protocol}: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error with {protocol}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error with {protocol}: {e}")
        return None

def test_directory_server():
    """Test the TLS directory server with both HTTP and HTTPS clients"""
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger('DirectoryTest')
    
    test_relay = TestRelay()
    long_term_pem, onion_pem = test_relay.get_public_keys_pem()
    
    upload_message = f"{test_relay.ip}{test_relay.port}{onion_pem}".encode()
    upload_signature = test_relay.sign_message(upload_message)
    
    upload_data = {
        "ip": test_relay.ip,
        "port": test_relay.port,
        "onion_key": onion_pem,
        "long_term_key": long_term_pem,
        "signature": upload_signature.hex()
    }
    
    heartbeat_message = f"{test_relay.ip}{test_relay.port}".encode()
    heartbeat_signature = test_relay.sign_message(heartbeat_message)
    
    heartbeat_data = {
        "ip": test_relay.ip,
        "port": test_relay.port,
        "signature": heartbeat_signature.hex()
    }
    
    tests = [
        ('upload_state', upload_data, 'POST'),
        ('heartbeat', heartbeat_data, 'POST'),
        ('download_states', None, 'GET')
    ]
    
    protocols = ['https', 'http']
    
    print("\nTesting TLS Directory Server")
    print("=" * 50)
    
    for protocol in protocols:
        print(f"\nTesting with {protocol.upper()}")
        print("-" * 30)
        
        for endpoint, data, method in tests:
            print(f"\nEndpoint: /{endpoint}")
            response = test_server_endpoint(protocol, endpoint, data, method)
            
            if response:
                print(f"Status Code: {response.status_code}")
                print(f"Response: {response.json()}")
                print(f"Protocol Used: {response.raw.version}")
                if hasattr(response.raw.connection, 'cipher_used'):
                    print(f"Cipher: {response.raw.connection.cipher_used}")
            else:
                print("No response received")

if __name__ == "__main__":
    test_directory_server()