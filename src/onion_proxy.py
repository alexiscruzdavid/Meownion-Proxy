from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import socket
import relay_directory
import ssl
import sys
import os



def open_tls_connection(src_ip, dest_ip, certfile, keyfile):
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # the long term identiy key is the keyfile
    server_context.load_cert_chain(certfile, keyfile)
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((src_ip, 8443))
    server_sock.listen(5)
    
    print('Onion Proxy listening on port 8443...')
    
    while True:
        client_sock, client_addr = server_sock.accept()
        print('Received connection from {}'.format(client_addr))
        
        tls_server_sock = server_context.wrap_socket(client_sock, server_side=True)

def establish_circuit():
    pass


        
def encrypt_message(byte_message, key):
    padder = padding.PKCS7(128).padder()
    byte_message = padder.update(byte_message) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(byte_message) + encryptor.finalize()
    return cipher_text

def handle_user_application():
    pass
    
def encrypt_message_with_circuit(message, circuit):
    for circuit_node in circuit:
        _, node_key = circuit_node.node_ip, circuit_node.node_key
        message = encrypt_message(message, node_key)
    return message


if __name__ == '__main__':
    print('Starting MeOwnion Proxy...')
    print(" /\_/\   ")
    print("( o.o )  ")
    print(" > ^ <   ")
    
    src_ip, certfile, keyfile = None, None, None
    if len(sys.argv) > 2:
        src_ip, certfile, keyfile = sys.argv[1:]
    elif len(sys.argv) > 1:
        src_ip = sys.argv[1]
        certfile = 'relay_cert.pem'
        keyfile = 'relay_key.pem'
    else:
        print('Help Description: Create an onion proxy')
        print('format: python3 onion_proxy src_ip certfile keyfile')
        exit(1)

    print('The chosen onion proxy ip is {}'.format(src_ip))
    
    
    while True:
        message = input('Type in your message ')
        dest_ip = input('Type in your destination ip ')
        print('Sending Message {} to {}'.format(message, dest_ip))
        circuit = relay_directory.fetch_circuit(src_ip, dest_ip)
        byte_cipher_text = encrypt_message_with_circuit(message.encode('iso-8859-1'), circuit)
        print('Your encrypted message is {}'.format(byte_cipher_text.decode('iso-8859-1')))
    
    
    