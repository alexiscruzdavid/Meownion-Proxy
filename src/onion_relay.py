from src.utils.certificates import Certificates
from typing import Tuple
import socket
import ssl
from . import start_tor as tor
import threading
import logging
import signal
import os
from tor_header import DefaultTorHeaderWrapper, RelayTorHeaderWrapper
from tor_encryption import decrypt_message

UPLOAD_INTERVAL = 60
DOWNLOAD_INTERVAL = 60
RELAY_SERVER_PORT = 31200
RELAY_CLIENT_PORT = 44000

TAGS = ['start', 'connection', 'circuit']



class OnionRelay:
    def __init__(self, name: str, ip: str, port:int, key:bytes):
        self.name = name
        self.ip = ip
        self.port = port
        self.key = key
        self.certificates = Certificates(name, ip)
        self.connections = {}
        self.connections_lock = threading.Lock()
        self.circuits = {}
        self.shutdown_flag = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        self.tags = {}
        for tag in TAGS:
            self.tags[tag] = f"[{tag.upper()}] : OnionRelay {self.name} :"

        logging.info(f"{self.tags['start']} initialized at {self.ip}:{self.port}")

    def start(self):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGHUP, self.shutdown)
        signal.signal(signal.SIGQUIT, self.shutdown)
        signal.signal(signal.SIGUSR1, self.shutdown)
        signal.signal(signal.SIGUSR2, self.shutdown)
        
        server_side_thread = threading.Thread(target=self.server_side_component, daemon=True)
        client_side_thread = threading.Thread(target=self.client_side_component, daemon=True)
        server_side_thread.start()
        client_side_thread.start()

        


    def client_side_component(self):
        while not self.shutdown_flag.is_set():
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # listen on own port for any incoming messages 
            client_listening_address = ('localhost', RELAY_CLIENT_PORT)
            
            client_socket.connect(client_listening_address)
            
            data = ''
            while True:
                tmp = client_socket.recv(1024).decode('utf-8')
                if not tmp:
                    break
                data += tmp
            
            if data:
                logging.info(f"{self.tags['connection']} unpacking message from {self.ip}:{RELAY_CLIENT_PORT}")
                
                data = decrypt_message(data, self.key)
                
                tor_message = DefaultTorHeaderWrapper()
                tor_message.unpackMessage(data)
                
                relay_message = RelayTorHeaderWrapper()
                relay_message.unpackMessage(tor_message.data)
                
                curr_circuit = self.circuits[relay_message.circID]
                
                # if we have reached the destination (i.e. if this node is the destination)
                if curr_circuit[-1].node_ip == self.ip:
                    # TODO udpate logic here
                    print(relay_message.data.decode('utf-8'))
                    break
                
                
                # find next relay and then send the data to them
                next_relay = None
                for index, circ_node in enumerate(curr_circuit):
                    if circ_node.node_ip == self.ip:
                        # once we reach the current node ip, then the next node ip is the next relay
                        next_relay = curr_circuit[index+1]
                        
                # make a relay socket to send to the next relay
                relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                next_relay_address = (next_relay.node_ip, RELAY_SERVER_PORT) 

                relay_socket.connect(next_relay_address)
                relay_socket.sendall(relay_message.data)                
            
            client_socket.close()
        

    def server_side_component(self):
        incoming_connections_thread = threading.Thread(target=self.accept_incoming_connections, daemon=True)
        with self.threads_lock:
            self.threads.append(incoming_connections_thread)
        incoming_connections_thread.start()

    def accept_incoming_connections(self):
        while not self.shutdown_flag.is_set():
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind((self.ip, self.port))
            server_sock.listen(tor.MAX_RELAYS + tor.MAX_CLIENTS)
            
            logging.info(f"{self.tags['connection']} listening on {self.ip}:{self.port}")
            
            client_sock, client_addr = server_sock.accept()
            tls_client_sock = None
            
            logging.info(f"{self.tags['connection']} accepted connection from {client_addr}")
            
            try:
                tls_client_sock = self.certificates.server_context.wrap_socket(client_sock, server_side=True)
                tls_client_sock_thread = threading.Thread(target=self.handle_incoming_connection, args=(tls_client_sock, client_addr), daemon=True)
                with self.threads_lock:
                    self.threads.append(tls_client_sock_thread)
                tls_client_sock_thread.start()
            except ssl.SSLError as e:
                logging.error(f"{self.tags['connection']} error with client {client_addr}: {e}")

    def handle_incoming_connection(self, tls_client_sock: ssl.SSLSocket, client_addr: Tuple[str, int]):
        '''
        TODO: Set up forwarding to next relay which will require locking on each socket
        '''
        with self.connections_lock:
            self.connections[client_addr] = tls_client_sock

        logging.info(f"{self.tags['connection']} received from {client_addr}")
        try:
            while not self.shutdown_flag.is_set():
                data = tls_client_sock.recv(1024)
                if not data:
                    break
                
                tls_client_sock.sendall(data)  # Echo the data back
        except Exception as e:
            logging.error(f"{self.tags['connection']} error with client {client_addr}: {e}")
            
        with self.connections_lock:
            self.connections.pop(client_addr)
            # Might need to retry connection, or just wait for handler
        tls_client_sock.close()
        logging.info(f"{self.tags['connection']} closed connection with {client_addr}")

    def start_outgoing_connection(self, ip: str, port: int):
        with self.connections_lock:
            if (ip, port) in self.connections:
                logging.info(f"{self.tags['connection']} already connected to {ip}:{port}")
                return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.connect((ip, port))
            tls_server_sock = self.certificates.client_context.wrap_socket(server_sock, server_hostname=ip)
            with self.connections_lock:
                self.connections[(ip, port)] = tls_server_sock
            tls_client_sock_thread = threading.Thread(target=self.handle_outgoing_connection, args=(tls_server_sock, ip, port), daemon=True)
            tls_client_sock_thread.start()
            logging.info(f"{self.tags['connection']} started connection to {ip}:{port}")

    def handle_outgoing_connection(self, tls_sock: ssl.SSLSocket, ip: str, port: int):
        """
        TODO: Do not close after sending initial data and then receiving
        """
        try:
            # Send initial message
            tls_sock.sendall(b"Hello from the client!")

            # Receive and process messages
            while True:
                try:
                    data = tls_sock.recv(1024)
                    if not data:
                        logging.info(f"{self.tags['connection']} received no data from {ip}:{port}")
                        break
                    logging.info(f"{self.tags['connection']} received from {ip}:{port}: {data.decode()}")
                except (ssl.SSLError, socket.timeout) as e:
                    logging.error(f"{self.tags['connection']} error with {ip}:{port}: {e}")
                    break
        except Exception as e:
            logging.error(f"{self.tags['connection']} error with {ip}:{port}: {e}")
        finally:
            with self.connections_lock:
                self.connections.pop((ip, port))
            tls_sock.close()
            logging.info(f"{self.tags['connection']} closed connection with {ip}:{port}")

    def upload_state(self):
        '''
        Upload relay state to directory server
        Request HTTP Format:
        POST /upload_state HTTP/1.1
            Host:
            Content-Type: application/json
            {
                'ip': str,
                'port': int,
                'onion_key',
                'long_term_key',
                'signature'
            }


        '''
        pass

    def download_states(self) -> Tuple[str, int]:
        '''
        Get states from directory server and update connections/states to relays
        If there is no connection already, assume you act as server

        Request HTTP Format:

        '''
        pass


    def update_connections(self) -> None:
        '''
        Update tls connections to relays
        '''
        pass

    def create_circuit(self):
        pass

    def extend_circuit(self):
        pass

    def destroy_circuit(self):
        pass

    def shutdown(self, signum=None, frame=None):
        for file_path in [
            self.certificates.tls_cert_file, self.certificates.tls_key_file, self.certificates.tls_csr_file,
            self.certificates.identity_key_file, self.certificates.identity_pub_key_file,
            self.certificates.onion_key_file, self.certificates.onion_pub_key_file
        ]:
            if os.path.exists(file_path):
                os.remove(file_path)
        logging.info(f"{self.tags['connection']} shutting down OnionRelay {self.name}")
        self.shutdown_flag.set()
        with self.threads_lock:
            for thread in self.threads:
                if thread.is_alive():
                    thread.join()
        with self.connections_lock:
            for connection in self.connections.values():
                connection.close()
        for file_path in [
            self.certificates.tls_cert_file, self.certificates.tls_key_file,
            self.certificates.identity_key_file, self.certificates.identity_pub_key_file,
            self.certificates.onion_key_file, self.certificates.onion_pub_key_file
        ]:
            if os.path.exists(file_path):
                os.remove(file_path)
        logging.info(f"{self.tags['connection']} OnionRelay {self.name} shut down")

    def __str__(self):
        return 'IP: {}:{} /nOnion Key: {} /nConnections :{}'.format(self.ip, self.port, self.onion_key, self.connections)
