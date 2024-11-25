from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import socket
import onion_relay
import ssl
import sys
import os
from onion_relay import OnionRelay
from tor_encryption import encrypt_message_with_circuit
from onion_directory import OnionDirectory
from tor_header import RelayTorHeader, DATA_SIZE, NULL_PORT


class OnionProxy():

    def __init__(self, src_ip, src_port): 
        self.relay = OnionRelay('Cat #{}'.format(src_port), src_ip, src_port)
        self.src_port = src_port
        self.src_ip = src_ip
        self.relay.start()
        self.get_destination()
        pass

# TODO: uncomment
    def get_destination(self):
        # self.dest_port = input('Type in your destination port ')
        return -1
    
    def get_states(self):
        return self.relay.download_states()
    
    # TODO: uncomment
    def get_destination_port(self):
        return -1
    
    def circuit_create_send(self, src_circuit_id: int, src_server_port: int, dst_server_port: int):
        self.relay.circuit_create_send(src_circuit_id, src_server_port, dst_server_port)

    def circuit_extend_send(self, src_circuit_id: int, dst_server_port: int):
        # Only proxy can send
        NULL_DATA = bytearray(DATA_SIZE)
        relay_message = RelayTorHeader()
        relay_message.initialize(src_circuit_id, 'EXTEND', dst_server_port, NULL_PORT, NULL_DATA)
        relay_message_data = relay_message.create_message()
        self.relay_message_to_next_hop(dst_server_port, relay_message_data)

    def relay_message_to_next_hop(self, port, message):
        self.relay.relay_message_to_next_hop(port, message)

    
    def start(self, circuit):
        print('Starting MeOwnion Proxy...')
        print(" /\_/\   ")
        print("( o.o )  ")
        print(" > ^ <   ")

        print('The chosen onion proxy port is {}'.format(self.src_port))

        
        # TODO: put in the while true loop
        # while True:
        message = input('Type in your message ')
        
        print('Sending Message {} to check constant')
        byte_cipher_text = encrypt_message_with_circuit(message.encode('iso-8859-1'), circuit, 1, 1)
        hex_cipher_text = ":".join("{:02x}".format(ord(c)) for c in byte_cipher_text.decode('iso-8859-1'))
        print('Your encrypted message is {}'.format(hex_cipher_text))
        self.relay.relay_message_to_next_hop(circuit[0]['port'], byte_cipher_text)
            
