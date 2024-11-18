import time

from src.utils.certificates import Certificates
from src.onion_directory import OnionDirectory
from typing import Tuple, List
import socket
import ssl
from . import start_tor as tor
import threading
import logging
import signal
import requests
import os

UPLOAD_INTERVAL = 60
DOWNLOAD_INTERVAL = 60


TAGS = ['start', 'connection', 'circuit']
HEARTBEAT_INTERVAL = 60



class OnionRelay:
    def __init__(self, name: str, ip: str, port: int, directory_ip: str, directory_port: int):
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
        for tag in TAGS:
            self.tags[tag] = f"[{tag.upper()}] : OnionRelay {self.name} :"

        logging.info(f"{self.tags['start']} initialized at {self.ip}:{self.port}")

    def start(self):
        self.upload_state()
        self.update_connections()
        self.threads.append(threading.Thread(target=self.heartbeat, daemon=True))
        # Make heartbeat a timed thread or something similar



    def accept_incoming_connections(self):
        pass

    def handle_incoming_connection(self, tls_client_sock: ssl.SSLSocket, client_addr: Tuple[str, int]):
        pass

    def start_outgoing_connection(self, ip: str, port: int):
        pass

    def handle_outgoing_connection(self, tls_sock: ssl.SSLSocket, ip: str, port: int):
        pass

    def upload_state(self):
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
            'onion_key': self.certificates.get_onion_key(),
            'long_term_key': self.certificates.get_identity_key(),
            'signature': self.certificates.sign(f"{self.ip}{self.port}{self.certificates.get_onion_key()}".encode()).hex()
        }
        response = requests.post(url, json=data)
        if response.status_code == 200:
            logging.info(f"{self.tags['start']} Successfully uploaded state to directory")
        else:
            logging.error(f"{self.tags['start']} Failed to upload state to directory: {response.text}")


    def update_connections(self) -> None:
        '''
        Get states from directory server and update connections/states to relays
        If there is no connection already, assume you act as server

        Request HTTP Format:

        '''
        url = f"http://{self.directory[0]}:{self.directory[1]}/download_states"
        response = requests.get(url)
        if response.status_code == 200:
            logging.info(f"{self.tags['start']} Successfully downloaded states from directory")
            states = response.json()

            for state in states:
                ip, port = state['ip'], state['port']
                if f"{ip}:{port}" not in self.connections:
                    self.start_outgoing_connection(ip, port)

    def heartbeat(self):
        """
        Send heartbeat to directory server at an interval
        """
        while True:
            url = f"http://{self.directory[0]}:{self.directory[1]}/heartbeat"
            data = {
                'ip': self.ip,
                'port': self.port,
                'signature': self.certificates.sign(f"{self.ip}{self.port}{self.certificates.get_onion_key()}".encode()).hex()
            }
            response = requests.post(url, json=data)
            if response.status_code == 200:
                logging.info(f"{self.tags['start']} Successfully sent heartbeat to directory")
            else:
                logging.error(f"{self.tags['start']} Failed to send heartbeat to directory: {response.text}")
            time.sleep(HEARTBEAT_INTERVAL)

    def create_circuit(self):
        pass

    def extend_circuit(self):
        pass

    def destroy_circuit(self):
        pass

    # def shutdown(self, signum=None, frame=None):
        # for file_path in [
        #     self.certificates.tls_cert_file, self.certificates.tls_key_file, self.certificates.tls_csr_file,
        #     self.certificates.identity_key_file, self.certificates.identity_pub_key_file,
        #     self.certificates.onion_key_file, self.certificates.onion_pub_key_file
        # ]:
        #     if os.path.exists(file_path):
        #         os.remove(file_path)
        # logging.info(f"{self.tags['connection']} shutting down OnionRelay {self.name}")
        # self.shutdown_flag.set()
        # with self.threads_lock:
        #     for thread in self.threads:
        #         if thread.is_alive():
        #             thread.join()
        # with self.connections_lock:
        #     for connection in self.connections.values():
        #         connection.close()
        # for file_path in [
        #     self.certificates.tls_cert_file, self.certificates.tls_key_file,
        #     self.certificates.identity_key_file, self.certificates.identity_pub_key_file,
        #     self.certificates.onion_key_file, self.certificates.onion_pub_key_file
        # ]:
        #     if os.path.exists(file_path):
        #         os.remove(file_path)
        # logging.info(f"{self.tags['connection']} OnionRelay {self.name} shut down")

    def __str__(self):
        return 'IP: {}:{} /nOnion Key: {} /nConnections :{}'.format(self.ip, self.port, self.onion_key, self.connections)
