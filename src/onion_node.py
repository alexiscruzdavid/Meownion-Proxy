import threading
import socket
import signal
import os
import logging
import requests
from typing import List
from utils.certificates import Certificates
from tor_encryption import decrypt_message
from tor_header import DefaultTorHeaderWrapper, RelayTorHeaderWrapper

MAX_RELAYS = 30
MAX_CLIENTS = 30

class OnionNode:
    def __init__(self, name: str, ip: str, port: int, directory_ip: str = "127.0.0.1", directory_port: int = 8001):
        self.name = name
        self.ip = ip
        self.port = port
        self.directory_ip = directory_ip
        self.directory_port = directory_port
        self.certificates = Certificates(name, ip)
        self.directory_url = f"http://{directory_ip}:{directory_port}"
        self.connections = {}
        self.circuits = {}
        self.threads = []

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.ip, self.port))
        self.server_sock.listen(MAX_RELAYS + MAX_CLIENTS)

        self.connections_lock = threading.Lock()
        self.circuits_lock = threading.Lock()
        self.threads_lock = threading.Lock()

        self.tags = {}
        logging.basicConfig(level=logging.INFO)

    def start(self):
        self.start_shutdown_listeners()

        incoming_connections_thread = threading.Thread(target=self.accept_incoming_connections, daemon=True)
        with self.threads_lock:
            self.threads.append(incoming_connections_thread)
        incoming_connections_thread.start()

    def create_circuit(self):
        pass

    def download_states(self) -> List[dict] | None:
        url = f"{self.directory_url}/download_states"
        response = requests.get(url)
        if response.status_code == 200:
            logging.info(f"{self.tags['start']} Successfully downloaded states from directory")
            return response.json()
        else:
            logging.error(f"{self.tags['start']} Failed to download states from directory: {response.text}")
        return None


    def accept_incoming_connections(self):
        while not self.shutdown_flag.is_set():
            logging.info(f"{self.tags['connection']} listening on {self.ip}:{self.port}")

            client_sock, client_addr = self.server_sock.accept()

            logging.info(f"{self.tags['connection']} accepted connection from {client_addr}")

            client_sock_thread = threading.Thread(target=self.handle_incoming_connection,
                                                  args=(client_sock, client_addr), daemon=True)
            with self.threads_lock:
                self.threads.append(client_sock_thread)
            client_sock_thread.start()


    def handle_incoming_connection(self, client_sock, client_addr):
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
                        next_relay = curr_circuit[index + 1]

                relay_message_thread = threading.Thread(target=self.relay_message_to_next, args=(
                next_relay.node_ip, next_relay.node_port, relay_message.data), daemon=True)
                with self.threads_lock:
                    self.threads.append(relay_message_thread)
                relay_message_thread.start()

        # with self.connections_lock:
        #     self.connections.pop(client_addr)
        # Might need to retry connection, or just wait for handler
        client_sock.close()
        logging.info(f"{self.tags['connection']} closed connection with {client_addr}")

    def relay_message_to_next_hop(self, next_relay_ip, next_relay_port, relay_message_data):
        # TODO: Get rid of for loop?
        # while not self.shutdown_flag.is_set():
        logging.info(f"{self.tags['connection']} unpacking message from {self.ip}:{self.port}")
        with self.connections_lock:
            next_relay_socket = self.connections[f"{next_relay_ip}:{next_relay_port}"]
        logging.info(f"{self.tags['connection']} sending message to {next_relay_ip}:{next_relay_port}")
        logging.info(f"{self.tags['connection']} socket: {next_relay_socket}")
        next_relay_socket.sendall(relay_message_data)

    def start_outgoing_connection(self, ip: str, port: int):
        logging.info(f"{self.tags['connection']} unpacking message from {self.ip}:{self.port}")

        next_relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        next_relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        next_relay_address = (ip, port)
        next_relay_socket.connect(next_relay_address)

        self.connections[f"{ip}:{port}"] = next_relay_socket


    def start_shutdown_listeners(self):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGHUP, self.shutdown)
        signal.signal(signal.SIGQUIT, self.shutdown)
        signal.signal(signal.SIGUSR1, self.shutdown)
        signal.signal(signal.SIGUSR2, self.shutdown)

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

