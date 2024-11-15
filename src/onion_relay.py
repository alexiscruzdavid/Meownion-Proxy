from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from utils.certificates import Certificates
from typing import List, Tuple
import socket
import relay_directory
import ssl
import time
import start_tor as tor
import sys
import os

UPLOAD_INTERVAL = 60
DOWNLOAD_INTERVAL = 60

class OnionRelay:
    def __init__(self, name: str, ip: str, port:int):
        self.name = name
        self.ip = ip
        self.port = port
        self.certificates = Certificates(name, ip)
        self.connections = {}
        self.circuits = {}
        self.start()

    def start(self):
        self.update_incoming_connections()
        self.update_outgoing_connections()
        self.upload_state()
        print('Onion Relay started at {}:{}'.format(self.ip, self.port))

    def create_socket(self):
        server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_context.load_cert_chain(self.certificates.tls_cert_file, self.certificates.tls_key_file)

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(tor.MAX_RELAYS + tor.MAX_CLIENTS)
        print('Onion Relay listening at {}:{}'.format(self.ip, self.port))

    def update_incoming_connections(self):
        '''
        Accept incoming tls connections from relays or clients
        :param dest_ip:
        :param dest_port:
        TODO: Prevent blocking the main thread
        '''
        while True:
            client_sock, client_addr = self.server_socket.accept()
            print('Received connection from {}'.format(client_addr))

            tls_server_sock = server_context.wrap_socket(client_sock, server_side=True)

    def update_outgoing_connections(self):
        pass

    def upload_state(self):
        '''
        Upload relay state to directory server
        '''
        while True:
            # TODO: upload state to directory server
            time.sleep(UPLOAD_INTERVAL)

    def download_states(self) -> Tuple[str, int]:
        '''
        Get states from directory server and update connections/states to relays
        '''
    #   Get actual states


    def update_connections(self) -> None:
        '''
        Update tls connections to relays
        '''
        while True:
            relays = self.download_states()
            time.sleep(DOWNLOAD_INTERVAL)

    def create_circuit(self):
        pass

    def extend_circuit(self):
        pass

    def destroy_circuit(self):
        pass

    def __str__(self):
        return 'IP: {}:{} /nOnion Key: {} /nConnections :{}'.format(self.ip, self.port, self.onion_key, self.connections)
