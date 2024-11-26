from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import socket
import onion_relay
import ssl
import sys
import os
from onion_relay import OnionRelay
from tor_encryption import encrypt_message_with_circuit, encrypt_message
from onion_directory import OnionDirectory
from tor_header import RelayTorHeader, DATA_SIZE, NULL_PORT
import logging
from utils.logging import Loggable

class OnionProxy(Loggable):
    def __init__(self, src_ip, src_port): 
        self.relay = OnionRelay('Cat #{}'.format(src_port), src_ip, src_port)
        super().__init__(log_type="OnionProxy", instance_name=self.relay.name, log_level=logging.INFO)
        self.port = src_port
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
    
    def circuit_create_send(self, circuit_id: int, src_server_port: int, dst_server_port: int):
        self.relay.circuit_create_send(circuit_id, src_server_port, dst_server_port)

    def circuit_extend_send(self, circuit_id: int, dst_server_port: int, partial_circuit: list[dict]):
        # Only proxy can send
        NULL_DATA = bytearray(DATA_SIZE)
        relay_message = RelayTorHeader()
        relay_message.initialize(circuit_id, 'EXTEND', dst_server_port, NULL_PORT, NULL_DATA)
        relay_message_data_part_1, relay_message_data_part_2 = relay_message.create_message()
        
        for circuit_node in partial_circuit:
            _, node_key = circuit_node['ip'], circuit_node['onion_key'].encode('iso-8859-1')
            relay_message_data_part_2 = encrypt_message(relay_message_data_part_2, node_key) 
        
        self.logger.info(f"Extending circuit {circuit_id} to {dst_server_port}")
        
        relay_message_data = relay_message_data_part_1 + relay_message_data_part_2
        
        
        forwarding_circuit, forwarding_port = self.relay.find_forwarding_port(circuit_id)
        if forwarding_port == -1:
            self.logger.info(f"HELP ME HELP ME HELP ME HELP ME")
        else:
            self.relay_message_to_next_hop(forwarding_port, relay_message_data)
            

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
            
