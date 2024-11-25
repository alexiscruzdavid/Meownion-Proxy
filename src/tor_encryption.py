import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from tor_header import RelayTorHeader
from hashlib import sha256

PADDING_BYTES = 128

def encrypt_message(byte_message: bytes, key: bytes):
    padder = padding.PKCS7(PADDING_BYTES).padder()

    byte_message = padder.update(byte_message) + padder.finalize()
    
    
    key = sha256(key).digest()[:16]
    # using key[:16] for the IV just for a proof of concept
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(byte_message) + encryptor.finalize()
    return cipher_text


def decrypt_message(cipher_text: bytes, key: bytes) -> bytes:
    key = sha256(key).digest()[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(key[:16]))
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(cipher_text) + decryptor.finalize()
    
    # unpadder = padding.PKCS7(PADDING_BYTES).unpadder()
    # byte_message = unpadder.update(padded_message) + unpadder.finalize()
    byte_message = padded_message
    return byte_message


# TODO: Fix relay tor header call
def encrypt_message_with_circuit(message, circuit, circID, streamID):
    for circuit_node in circuit:
        _, node_key = circuit_node['ip'], circuit_node['onion_key'].encode('iso-8859-1')
        
        curr_relay_header = RelayTorHeader(circID, 'RELAY_DATA', streamID, 0, len(message), 'RELAY', message)
        relay_message = curr_relay_header.create_message()
        
        
        message = encrypt_message(tor_message, node_key)    
    return message
