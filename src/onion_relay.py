import time

from utils.certificates import Certificates
from onion_directory import OnionDirectory
from typing import Tuple, List
import socket
import ssl
import threading
import logging
import signal
import requests
import os
from tor_encryption import decrypt_message
from tor_header import DefaultTorHeaderWrapper, RelayTorHeaderWrapper

UPLOAD_INTERVAL = 60
DOWNLOAD_INTERVAL = 60
NUMER_OF_RELAYS = 5
MAX_RELAYS = 30
MAX_CLIENTS = 30


TAGS = ['start', 'connection', 'circuit']
HEARTBEAT_INTERVAL = 60




class OnionRelay:
    def __init__(self, name: str, ip: str, port: int, directory_ip: str = "127.0.0.1", directory_port: int = 8001):
        self.name = name
        self.ip = ip
        self.port = port
        self.certificates = Certificates(name, ip)
        self.directory = (directory_ip, directory_port)
        self.connections = {}
        self.connections_lock = threading.Lock()
        self.circuits = {}
        self.shutdown_flag = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        self.tags = {}
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind the socket to own ip and listen for incoming connections
        self.server_sock.bind((self.ip, self.port)) 
        self.server_sock.listen(MAX_RELAYS + MAX_CLIENTS)
        
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

        self.upload_state()
        self.update_connections()

        self.threads.append(threading.Thread(target=self.heartbeat, daemon=True))
        # Make heartbeat a timed thread or something similar
        incoming_connections_thread = threading.Thread(target=self.accept_incoming_connections, daemon=True)
        with self.threads_lock:
            self.threads.append(incoming_connections_thread)
        incoming_connections_thread.start()



    def relay_message_to_next_hop(self, next_relay_ip, next_relay_port, relay_message_data):
        while not self.shutdown_flag.is_set():
            logging.info(f"{self.tags['connection']} unpacking message from {self.ip}:{self.port}")
            with self.connections_lock:
                next_relay_socket = self.connections[f"{next_relay_ip}:{next_relay_port}"]
            logging.info(f"{self.tags['connection']} sending message to {next_relay_ip}:{next_relay_port}")
            logging.info(f"{self.tags['connection']} socket: {next_relay_socket}")
            next_relay_socket.sendall(relay_message_data)                            
            
    def accept_incoming_connections(self):
        while not self.shutdown_flag.is_set():
            
            logging.info(f"{self.tags['connection']} listening on {self.ip}:{self.port}")
            
            client_sock, client_addr = self.server_sock.accept()
            
            logging.info(f"{self.tags['connection']} accepted connection from {client_addr}")
            
            client_sock_thread = threading.Thread(target=self.handle_incoming_connection, args=(client_sock, client_addr), daemon=True)
            with self.threads_lock:
                self.threads.append(client_sock_thread)
            client_sock_thread.start()

    def handle_incoming_connection(self, client_sock, client_addr):
        '''
        TODO: Set up forwarding to next relay which will require locking on each socket
        '''
        # with self.connections_lock:
        #     self.connections[client_addr] = client_sock

        logging.info(f"{self.tags['connection']} received from {client_addr}")
        
        data = bytes()
        while not self.shutdown_flag.is_set():
            temp = client_sock.recv(1024)
            if not temp:
                break
            data += temp
        
        if data:

            data = decrypt_message(data, self.key)
            
            tor_message = DefaultTorHeaderWrapper()
            tor_message.unpackMessage(data)
            logging.info(f"command is {tor_message.cmd} and port is {tor_message}")
            relay_message = RelayTorHeaderWrapper()
            relay_message.unpackMessage(tor_message.data)
        
            curr_circuit = self.circuits[relay_message.circID]
            
            # if we have reached the destination (i.e. if this node is the destination)
            if curr_circuit[-1].node_ip == self.ip:
                # TODO udpate logic here
                print(relay_message.data.decode('iso-8859-1'))
            else:    
                # find next relay and then send the data to them
                next_relay = None
                for index, circ_node in enumerate(curr_circuit):
                    if circ_node.node_ip == self.ip:
                        # once we reach the current node ip, then the next node ip is the next relay
                        next_relay = curr_circuit[index+1]
                
                
                relay_message_thread = threading.Thread(target=self.relay_message_to_next, args=(next_relay.node_ip, next_relay.node_port, relay_message.data), daemon=True)
                with self.threads_lock:
                    self.threads.append(relay_message_thread)
                relay_message_thread.start()
        
        # with self.connections_lock:
        #     self.connections.pop(client_addr)
            # Might need to retry connection, or just wait for handler
        client_sock.close()
        logging.info(f"{self.tags['connection']} closed connection with {client_addr}")


    def start_outgoing_connection(self, ip: str, port: int):
        logging.info(f"{self.tags['connection']} unpacking message from {self.ip}:{self.port}")
        
        next_relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        next_relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        next_relay_address = (ip, port)
        next_relay_socket.connect(next_relay_address)

        self.connections[f"{ip}:{port}"] = next_relay_socket

    def handle_outgoing_connection(self, tls_sock: ssl.SSLSocket, ip: str, port: int):
        pass

    def upload_state(self) -> bool:
        """
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
        """
        url = f"http://{self.directory[0]}:{self.directory[1]}/upload_state"
        data = {
            'ip': self.ip,
            'port': self.port,
            'onion_key': self.certificates.get_onion_key().decode('iso-8859-1'),
            'long_term_key': self.certificates.get_identity_key().decode('iso-8859-1'),
            'signature': self.certificates.sign(f"{self.ip}{self.port}{self.certificates.get_onion_key().decode('iso-8859-1')}".encode('iso-8859-1')).hex()
        }
        response = requests.post(url, json=data)
        if response.status_code == 200:
            logging.info(f"{self.tags['start']} Successfully uploaded state to directory")
            return True
        else:
            logging.error(f"{self.tags['start']} Failed to upload state to directory: {response.text}")
            return False

    def download_states(self) -> List[dict] | None:
        url = f"http://{self.directory[0]}:{self.directory[1]}/download_states"
        response = requests.get(url)
        if response.status_code == 200:
            logging.info(f"{self.tags['start']} Successfully downloaded states from directory")
            return response.json()
        else:
            logging.error(f"{self.tags['start']} Failed to download states from directory: {response.text}")
        return None

    def update_connections(self) -> None:
        '''
        Get states from directory server and update connections/states to relays
        If there is no connection already, assume you act as server

        Request HTTP Format:

        '''
        states = self.download_states()
        with self.connections_lock:
            if states is None:
                logging.error(f"{self.tags['start']} Failed to download states from directory")
                return
            for state in states:
                ip, port = state['ip'], state['port']
                if (port != self.port) and (f"{ip}:{port}" not in self.connections):
                    self.start_outgoing_connection(ip, port)

    def heartbeat_periodic(self):
        """
        Send heartbeat to directory server at an interval
        """
        while True:
            self.heartbeat()
            time.sleep(HEARTBEAT_INTERVAL)

    def heartbeat(self) -> bool:
        url = f"http://{self.directory[0]}:{self.directory[1]}/heartbeat"
        data = {
            'ip': self.ip,
            'port': self.port,
            'signature': self.certificates.sign(
                f"{self.ip}{self.port}".encode('iso-8859-1')).hex()
        }
        response = requests.post(url, json=data)
        if response.status_code == 200:
            logging.info(f"{self.tags['start']} Successfully sent heartbeat to directory")
            return True
        else:
            logging.error(f"{self.tags['start']} Failed to send heartbeat to directory: {response.text}")
            return False


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
            print(f'closing connections: {self.connections.values()}')
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