import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from tor_header import RelayTorHeader
from hashlib import sha256

PADDING_BYTES = 128
MESSAGE_SIZE = 264 + 8

def encrypt_message(byte_message: bytes, key: bytes):
    
    print('encryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencryptingencrypting')
    key = sha256(key).digest()[:32]
    print(key)
    
    
    byte_message = byte_message[:MESSAGE_SIZE].ljust(MESSAGE_SIZE, b'\x00')

    # using key[:16] for the IV just for a proof of concept
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(byte_message) + encryptor.finalize()
    return cipher_text


def decrypt_message(cipher_text: bytes, key: bytes) -> bytes:
    print('decryptingdecryptingdecryptingdecryptingdecryptingdecryptingdecryptingdecryptingdecryptingdecryptingdecryptingdecryptingdecryptingdecrypting')
    key = sha256(key).digest()[:32]
    print(key)
    

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    

    decryptor = cipher.decryptor()

    byte_message = decryptor.update(cipher_text) + decryptor.finalize()
    # unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    # byte_message = unpadder.update(padded_message) + unpadder.finalize()
    return byte_message


# TODO: Fix relay tor header call
def encrypt_message_with_circuit(message, circuit, circID, streamID):
    curr_relay_header = RelayTorHeader()
    curr_relay_header.initialize(circID, 'RELAY_DATA', streamID, 0, len(message), 'RELAY', message)
    relay_message_part_1, relay_message_part_2 = curr_relay_header.create_message()
    for circuit_node in circuit:
        _, node_key = circuit_node['ip'], circuit_node['onion_key'].encode('iso-8859-1')
        
        relay_message_part_2 = encrypt_message(relay_message_part_2, node_key)    
    return relay_message_part_1 + relay_message_part_2
