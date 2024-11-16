import unittest
from unittest.mock import MagicMock, patch
import socket
import ssl
from src.onion_relay import OnionRelay

class TestOnionRelay(unittest.TestCase):

    def test_initialization(self):
        relay = OnionRelay("Relay1", "127.0.0.1", 8080)

        self.assertEqual(relay.name, "Relay1")
        self.assertEqual(relay.ip, "127.0.0.1")
        self.assertEqual(relay.port, 8080)
        self.assertIsInstance(relay.connections, dict)
        self.assertIsInstance(relay.circuits, dict)

    @patch("ssl.SSLSocket")
    def test_handle_incoming_connection(self, mock_ssl_socket):
        relay = OnionRelay("Relay1", "127.0.0.1", 8080)
        client_addr = ("192.168.1.1", 12345)

        mock_ssl_socket.recv = MagicMock(side_effect=[b"Hello", b"World", b""])
        mock_ssl_socket.sendall = MagicMock()

        relay.handle_incoming_connection(mock_ssl_socket, client_addr)

        # Assert the data was received and echoed back
        self.assertEqual(mock_ssl_socket.recv.call_count, 3)
        mock_ssl_socket.sendall.assert_any_call(b"Hello")
        mock_ssl_socket.sendall.assert_any_call(b"World")

        # Ensure the connection was removed
        self.assertNotIn(client_addr, relay.connections)

    @patch("ssl.SSLSocket")
    @patch("socket.socket")
    def test_handle_outgoing_connection(self, mock_socket, mock_ssl_socket):
        relay = OnionRelay("Relay1", "127.0.0.1", 8080)
        ip, port = "192.168.1.2", 8081

        mock_socket.return_value.connect = MagicMock()
        mock_ssl_socket.recv = MagicMock(side_effect=[b"Response1", b"Response2", b""])
        mock_ssl_socket.sendall = MagicMock()

        relay.handle_outgoing_connection(mock_ssl_socket, ip, port)

        # Assert the data was received
        self.assertEqual(mock_ssl_socket.recv.call_count, 3)
        mock_ssl_socket.sendall.assert_called_with(b"Hello from the client!")

        # Ensure the connection was removed
        self.assertNotIn((ip, port), relay.connections)

    @patch("ssl.SSLSocket")
    def test_handle_incoming_connection_timeout(self, mock_ssl_socket):
        relay = OnionRelay("Relay1", "127.0.0.1", 8080)
        client_addr = ("192.168.1.1", 12345)

        mock_ssl_socket.recv = MagicMock(side_effect=socket.timeout)
        mock_ssl_socket.close = MagicMock()

        relay.handle_incoming_connection(mock_ssl_socket, client_addr)

        # Ensure the connection was closed on timeout
        mock_ssl_socket.close.assert_called_once()
        self.assertNotIn(client_addr, relay.connections)

    @patch("ssl.SSLSocket")
    def test_accept_incoming_connections_tls_error(self, mock_ssl_socket):
        relay = OnionRelay("Relay1", "127.0.0.1", 8080)

        mock_ssl_socket.wrap_socket = MagicMock(side_effect=ssl.SSLError("TLS handshake failed"))
        mock_socket = MagicMock()
        mock_socket.accept = MagicMock(return_value=(mock_ssl_socket, ("192.168.1.1", 12345)))

        with patch("socket.socket", return_value=mock_socket):
            with self.assertLogs(level="ERROR") as log:
                relay.accept_incoming_connections()

                # Ensure the error was logged
                self.assertTrue(any("TLS handshake failed" in message for message in log.output))


if __name__ == "__main__":
    unittest.main()
