import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from tor_header import DefaultTorHeaderWrapper, RelayTorHeaderWrapper

def encrypt_message(byte_message: bytes, key: bytes):
    padder = padding.PKCS7(128).padder()
    byte_message = padder.update(byte_message) + padder.finalize()
    
    # using key[:16] for the IV just for a proof of concept
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(byte_message) + encryptor.finalize()
    return cipher_text


def decrypt_message(cipher_text: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]))
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(cipher_text) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    byte_message = unpadder.update(padded_message) + unpadder.finalize()
    
    return byte_message

def encrypt_message_with_circuit(message, circuit, circID, streamID):
    for circuit_node in circuit:
        _, node_key = circuit_node.node_ip, circuit_node.node_key
        
        curr_relay_header = RelayTorHeaderWrapper(circID, 'RELAY_DATA', streamID, 0, len(message), 'RELAY', message)
        relay_message = curr_relay_header.create_message()
        
        curr_tor_header = DefaultTorHeaderWrapper(circID, 'RELAY', len(relay_message), relay_message)
        tor_message = curr_tor_header.create_message()
        
        message = encrypt_message(tor_message, node_key)    
    return message