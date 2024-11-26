'''
11/23 Notes
    - Got rid of start_outgoing_connection in update_connections since we are not going to reuse connections
    - Next hop changed to starting a brand new socket rather than reusing connections
'''

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
import random
import os
from tor_encryption import decrypt_message, encrypt_message
from tor_header import RelayTorHeader, RELAY_CMD_ENUM, DATA_SIZE, NULL_PORT
from utils.logging import Loggable

UPLOAD_INTERVAL = 60
DOWNLOAD_INTERVAL = 60
NUMER_OF_RELAYS = 5
MAX_RELAYS = 30
MAX_CLIENTS = 30
RELAY_IP = "127.0.0.1"



class OnionRelay(Loggable):
    def __init__(self, name: str, ip: str, port: int, directory_ip: str = "127.0.0.1", directory_port: int = 8001):
        super().__init__(log_type="OnionRelay", instance_name=name)
        self.name = name
        self.ip = ip
        self.port = port
        self.certificates = Certificates(name, ip)
        self.directory = (directory_ip, directory_port)
        self.connections = {}
        self.connections_lock = threading.Lock()
        self.all_circuits = set()
        self.circuit_forwarding = {}
        self.shutdown_flag = threading.Event()
        self.threads = []
        self.threads_lock = threading.Lock()
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind the socket to own ip and listen for incoming connections
        self.server_sock.bind((self.ip, self.port)) 
        self.server_sock.listen(MAX_RELAYS + MAX_CLIENTS)

        self.logger.info(f"initializing at {self.ip}:{self.port}")

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

    def circuit_create_received(self, src_circuit_id, source_server_port):
        self.logger.info(f"creating new circuit, already have {self.all_circuits} and {self.circuit_forwarding}")
        self.all_circuits.add(src_circuit_id)
        self.circuit_forwarding[src_circuit_id] = (source_server_port, None)
        self.logger.info(f"allcircuts ={self.all_circuits} and circutforwarding={self.circuit_forwarding}")
        
    def circuit_extend_received(self, src_circuit_id: int, dst_server_port):
        forwarding_circuit, forwarding_port = self.find_forwarding_port(src_circuit_id)
        if forwarding_port == -1:
            dst_circuit_id = random.randint(1, 1000)
            while dst_circuit_id in self.all_circuits:
                dst_circuit_id = random.randint(1, 1000)
            self.all_circuits.add(dst_circuit_id)
            self.circuit_forwarding[src_circuit_id][1] = (dst_circuit_id, dst_server_port)
            self.circuit_create_send(dst_circuit_id, self.port, dst_server_port)
        else:
            NULL_DATA = bytearray(DATA_SIZE)
            relay_message = RelayTorHeader()
            relay_message.initialize(forwarding_circuit, 'CREATE', NULL_PORT, forwarding_port, NULL_DATA)
            relay_message_1, relay_message_2 = relay_message.create_message()
            self.relay_message_to_next_hop(forwarding_port, relay_message_1 + relay_message_2)
            

    def circuit_create_send(self, src_circuit_id: int, src_server_port: int, dst_server_port: int):
        NULL_DATA = bytearray(DATA_SIZE)
        relay_message = RelayTorHeader()
        relay_message.initialize(src_circuit_id, 'CREATE', src_server_port, NULL_PORT, NULL_DATA)
        relay_message_data_part_1, relay_message_data_part_2 = relay_message.create_message()
        for relay_state in self.relay_states:
            if relay_state['port'] == dst_server_port:
                relay_message_data_part_2 = encrypt_message(relay_message_data_part_2, relay_state['onion_key'].encode('iso-8859-1'))
                break
        relay_message_data = relay_message_data_part_1 + relay_message_data_part_2
        self.relay_message_to_next_hop(dst_server_port, relay_message_data)

    def relay_data_received(self, src_circuit_id: int, data: bytearray):
        for relay_state in self.relay_states:
            if relay_state['port'] == dst_server_port:
                dst_relay_onion_key = relay_state['onion_key']        
        
        # Going forwards
        if src_circuit_id in self.circuit_forwarding:
            dst_circuit_id, dst_server_port = self.circuit_forwarding[src_circuit_id][1]
            relay_message = RelayTorHeader()
            relay_message.initialize(dst_circuit_id, 'RELAY_DATA', NULL_PORT, NULL_PORT, data)
            relay_message_data_part_1, relay_message_data_part_2 = relay_message.create_message()
            
            relay_message_data_part_2 = encrypt_message(relay_message_data_part_2, dst_relay_onion_key)
            relay_message_data = relay_message_data_part_1 + relay_message_data_part_2
            self.relay_message_to_next_hop(dst_server_port, relay_message_data.decode())
        # Going backwards, check values
        else:
            dst_circuit_id, dst_server_port = self.find_returning_port(src_circuit_id)
            relay_message = RelayTorHeader()
            relay_message.initialize(dst_circuit_id, 'RELAY_DATA', NULL_PORT, NULL_PORT, data)
            relay_message_data_part_1, relay_message_data_part_2 = relay_message.create_message()
            relay_message_data_part_2 = encrypt_message(relay_message_data_part_2, dst_relay_onion_key.decode())
            relay_message_data = relay_message_data_part_1 + relay_message_data_part_2
            self.relay_message_to_next_hop(dst_server_port, relay_message_data)
     
    def find_returning_port(self, src_circuit_id: int):
        for returning_circuit_id, (returning_server_port, (forwarding_circuit_id, _)) in self.circuit_forwarding.items():
            if src_circuit_id == forwarding_circuit_id:
                return returning_circuit_id, returning_server_port
        return -1, -1
    
    def find_forwarding_port(self, src_circuit_id: int):
        circuit_forwarding_value = self.circuit_forwarding.get(src_circuit_id, -1)
        if circuit_forwarding_value != -1 and circuit_forwarding_value[1] is not None:
            circuit_forwarding_id = circuit_forwarding_value[1]
            circuit_forwarding_port = circuit_forwarding_value[1][1]
            return circuit_forwarding_id, circuit_forwarding_port
        return -1, -1

    def relay_message_to_next_hop(self, next_relay_port, relay_message_data):
        self.logger.info(f"creating message from {self.ip}:{self.port}")
        # TODO Go back to using connections eventually first IP, then storing sockets
        # with self.connections_lock:
        #     next_relay_socket = self.connections[f"{next_relay_ip}:{next_relay_port}"]
        next_relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        next_relay_socket.connect((RELAY_IP, next_relay_port))
        self.logger.info(f"sending message to {next_relay_port}")
        next_relay_socket.sendall(relay_message_data)                            
            
    def accept_incoming_connections(self):
        while not self.shutdown_flag.is_set():
            
            self.logger.info(f"istening on {self.ip}:{self.port}")
            
            client_sock, client_addr = self.server_sock.accept()
            
            self.logger.info(f"accepted connection from {client_addr}")
            
            client_sock_thread = threading.Thread(target=self.handle_incoming_connection, args=(client_sock, client_addr), daemon=True)
            with self.threads_lock:
                self.threads.append(client_sock_thread)
            client_sock_thread.start()

    def handle_incoming_connection(self, client_sock, client_addr):
        '''
        TODO: Change close function to be when done
        '''

        self.logger.info(f"received from {client_addr}")
        
        data = bytes()
        while True:
            temp = client_sock.recv(1024)
            if not temp:
                break
            data += temp
        self.logger.info(f"Data {data.decode('iso-8859-1')[:2]}")
        self.logger.info(f"Data Size {len(data)}")
        if data:
            # TODO: Haven't encrypted it yet, but we are still decrypting it. Create message, ... is not
            # encrypting the message
            data_part_1 = data[:6]
            data_part_2 = decrypt_message(data[6:], self.certificates.get_onion_key())
            data = data_part_1 + data_part_2
            self.logger.info(f"Decrypted Data {data.decode('iso-8859-1')}")
            relay_message = RelayTorHeader()
            relay_message.unpack_message(data)
            self.logger.info(f"src_port is {relay_message.src_server_port} and dst_port is {relay_message.dst_server_port}")
            self.logger.info(f"command is {relay_message.cmd} and circId is {relay_message.circID}")
            self.logger.info(f"Data is {relay_message.data}")

            if relay_message.cmd == RELAY_CMD_ENUM['CREATE']:
                self.logger.info(f"Creating circuit {relay_message.circID} from {relay_message.src_server_port}") 
                self.circuit_create_received(relay_message.circID, relay_message.src_server_port)
                self.logger.info(f"Created circuit {relay_message.circID} from {relay_message.src_server_port}")

            elif relay_message.cmd == RELAY_CMD_ENUM['EXTEND']:
                self.logger.info(f"Extending circuit {relay_message.circID} to {relay_message.dst_server_port}")
                self.circuit_extend_received(relay_message.circID, relay_message.dst_server_port)
                self.logger.info(f"Extended circuit {relay_message.circID} to {relay_message.dst_server_port}")

            elif relay_message.cmd == RELAY_CMD_ENUM['RELAY_DATA']:
                if relay_message.circID in self.all_circuits:
                    self.relay_data_received(relay_message.circID, relay_message.data)
                else:
                    self.logger.info(f"Received message: {relay_message.data} from {client_addr}")
                    # TODO: Send backwards

        client_sock.close()
        self.logger.info(f"closed connection with {client_addr}")


    def start_outgoing_connection(self, ip: str, port: int):
        self.logger.info(f"starting outgoing connection to {ip}:{port}")

        next_relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # next_relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
            self.logger.info(f"Successfully uploaded state to directory")
            return True
        else:
            logging.error(f"Failed to upload state to directory: {response.text}")
            return False

    def download_states(self) -> List[dict] | None:
        url = f"http://{self.directory[0]}:{self.directory[1]}/download_states"
        response = requests.get(url)
        if response.status_code == 200:
            self.logger.info(f"Successfully downloaded states from directory")
            return response.json()
        else:
            logging.error(f"Failed to download states from directory: {response.text}")
        return None

    def update_connections(self) -> None:
        '''
        Get states from directory server and update connections/states to relays
        If there is no connection already, assume you act as server
        Request HTTP Format:

        '''
        self.relay_states = self.download_states()
        if self.relay_states is None:
            logging.error(f"Failed to download states from directory")
            return
        # for state in relay_states:
            
        #     ip, port = state['ip'], state['port'], state['onion_key']
        #     if (port != self.port) and (f"{ip}:{port}" not in self.connections):
        #         pass
        #             #TODO uncomment once getting single socket storage over ip
        #             # self.start_outgoing_connection(ip, port)

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
            self.logger.info(f"Successfully sent heartbeat to directory")
            return True
        else:
            logging.error(f"Failed to send heartbeat to directory: {response.text}")
            return False

    def shutdown(self, signum=None, frame=None):
        for file_path in [
            self.certificates.tls_cert_file, self.certificates.tls_key_file, self.certificates.tls_csr_file,
            self.certificates.identity_key_file, self.certificates.identity_pub_key_file,
            self.certificates.onion_key_file, self.certificates.onion_pub_key_file
        ]:
            if os.path.exists(file_path):
                os.remove(file_path)
        self.logger.info(f"shutting down OnionRelay {self.name}")
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
        self.logger.info(f"OnionRelay {self.name} shut down")        
        

    def __str__(self):
        return 'IP: {}:{} /nOnion Key: {} /nConnections :{}'.format(self.ip, self.port, self.onion_key, self.connections)