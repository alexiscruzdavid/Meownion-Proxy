import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import socket
import ssl
from src.utils.certificates import Certificates
import threading
from threading import Thread
from src.onion_relay import OnionRelay  # Assuming the class OnionRelay is in a file named 'my_module.py'
import random
import time




class TestOnionRelay(unittest.TestCase):

    def setUp(self):
        # Use a random port to avoid conflicts during parallel tests
        self.port = random.randint(10000, 60000)
        self.relay = OnionRelay("TestRelay", "127.0.0.1", self.port)
        self.relay.certificates.start()

        time.sleep(1)

    def test_initialization(self):
        self.assertEqual(self.relay.name, "TestRelay")
        self.assertEqual(self.relay.ip, "127.0.0.1")
        self.assertEqual(self.relay.port, self.port)
        self.assertFalse(self.relay.shutdown_flag.is_set())

    def test_accept_incoming_connections(self):
        self.relay.start()

        client_ip = "127.0.0.1"
        client_port = random.randint(10000, 60000)


        # Attempt to connect to the server using the specified client IP and port
        with socket.create_connection((self.relay.ip, self.relay.port),
                                      source_address=(client_ip, client_port)) as client_sock:
            with self.relay.certificates.client_context.wrap_socket(client_sock, server_hostname=self.relay.ip) as tls_client_sock:
                message = b"Hello Relay"
                tls_client_sock.sendall(message)
                response = tls_client_sock.recv(1024)
                self.assertEqual(response, message)



    def test_shutdown(self):
        self.relay.shutdown()
        self.assertTrue(self.relay.shutdown_flag.is_set())
        with self.relay.threads_lock:
            for thread in self.relay.threads:
                self.assertFalse(thread.is_alive(), f"Thread {thread.name} should be stopped after shutdown")
        with self.relay.connections_lock:
            for connection in self.relay.connections.values():
                self.assertTrue(connection._closed, "Connection should be closed after shutdown")

    def tearDown(self):
        self.relay.shutdown()  # Stop the relay
        self.relay = None
        # if self.relay_thread.is_alive():
        #     self.relay_thread.join()  # Ensure the relay thread is joined before ending the test


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()


