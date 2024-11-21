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


class OnionProxy():

    def __init__(self, src_ip, src_port): 
        self.relay = OnionRelay('Cat #{}'.format(src_port), src_ip, src_port)
        self.src_port = src_port
        self.src_ip = src_ip
        self.relay.start()
        self.get_destination()
        pass

    def get_destination(self):
        self.dest_port = input('Type in your destination port ')
    
    def get_states(self):
        return self.relay.download_states()
    
    def get_destination_port(self):
        return self.dest_port
    
    def start(self, circuit):
        print('Starting MeOwnion Proxy...')
        print(" /\_/\   ")
        print("( o.o )  ")
        print(" > ^ <   ")

        print('The chosen onion proxy port is {}'.format(self.src_port))

        
        # TODO: put in the while true loop
        # while True:
        message = input('Type in your message ')
        print('Sending Message {} to {}'.format(message, self.dest_port))
        byte_cipher_text = encrypt_message_with_circuit(message.encode('iso-8859-1'), circuit, 1, 1)
        hex_cipher_text = ":".join("{:02x}".format(ord(c)) for c in byte_cipher_text.decode('iso-8859-1'))
        print('Your encrypted message is {}'.format(hex_cipher_text))
        self.relay.relay_message_to_next_hop(circuit[0]['ip'], circuit[0]['port'], byte_cipher_text)
            
