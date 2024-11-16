from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from utils.certificates import Certificates
from typing import List, Tuple
import socket
import relay_directory
import ssl
import time
import start_tor as tor
import threading


UPLOAD_INTERVAL = 60
DOWNLOAD_INTERVAL = 60

class OnionRelay:
    def __init__(self, name: str, ip: str, port:int):
        self.name = name
        self.ip = ip
        self.port = port
        self.certificates = Certificates(name, ip)
        self.connections = {}
        self.connections_lock = threading.Lock()
        self.circuits = {}
        self.start()

    def start(self):
        incoming_connections_thread = threading.Thread(target=self.accept_incoming_connections, daemon=True)
        print('Onion Relay listening at {}:{}'.format(self.ip, self.port))
        incoming_connections_thread.start()


        print('Onion Relay started at {}:{}'.format(self.ip, self.port))

    def accept_incoming_connections(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((self.ip, self.port))
        server_sock.listen(tor.MAX_RELAYS + tor.MAX_CLIENTS)

        while True:
            client_sock, client_addr = server_sock.accept()
            print('Received connection from {}'.format(client_addr))
            try:
                tls_client_sock = self.certificates.server_context.wrap_socket(client_sock, server_side=True)
                tls_client_sock_thread = threading.Thread(target=self.handle_incoming_connection, args=(tls_client_sock, client_addr), daemon=True)
                tls_client_sock_thread.start()

            except ssl.SSLError as e:
                print(f"TLS handshake failed or handler thread exited for {client_addr}: {e}")
                client_sock.close()

    def handle_incoming_connection(self, tls_client_sock: ssl.SSLSocket, client_addr: Tuple[str, int]):
        '''
        TODO: Set up forwarding to next relay which will require locking on each socket
        '''
        with self.connections_lock:
            self.connections[client_addr] = tls_client_sock

        try:
            while True:
                data = tls_client_sock.recv(1024)
                if not data:
                    break
                print(f"Received from {client_addr}: {data.decode()}")
                tls_client_sock.sendall(data)  # Echo the data back
        except Exception as e:
            print(f"Error with client {client_addr}: {e}")
        finally:
            with self.connections_lock:
                self.connections.pop(client_addr)
                # Might need to retry connection, or just wait for handler
            tls_client_sock.close()
            print(f"Connection with {client_addr} closed.")

    def start_outgoing_connection(self, ip: str, port: int):
        if (ip, port) in self.connections:
            # TODO: Add the constraint that it should try a ping first, or verify somehow
            print('Already connected to relay {}:{}'.format(ip, port))
            return

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((ip, port))
        tls_client_sock = self.certificates.client_context.wrap_socket(client_sock, server_hostname=ip)
        with self.connections_lock:
            self.connections[(ip, port)] = tls_client_sock
        print('Connected to relay {}:{}'.format(ip, port))

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
