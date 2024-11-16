import unittest
import subprocess
from unittest.mock import patch, MagicMock
from src.utils.certificates import Certificates, generate_ssl_cert, generate_rsa_key_pair, check_openssl
import os
import shutil


class TestCertificatesFunctions(unittest.TestCase):
    @patch("ssl.create_default_context")
    @patch("src.utils.certificates.generate_ssl_cert")
    @patch("src.utils.certificates.generate_rsa_key_pair")
    @patch("os.path.join")
    def test_certificates_initialization_with_mocked_dependencies(self, mock_path_join, mock_generate_rsa_key_pair, mock_generate_ssl_cert, mock_ssl_context):
        mock_path_join.side_effect = lambda *args: "/".join(args)

        mock_server_context = MagicMock()
        mock_client_context = MagicMock()
        mock_ssl_context.side_effect = [mock_server_context, mock_client_context]

        cert = Certificates("Relay1", "127.0.0.1")

        # Test attribute assignments
        self.assertEqual(cert.name, "Relay1")
        self.assertIn("Relay1_cert.pem", cert.tls_cert_file)
        self.assertIn("Relay1_key.pem", cert.tls_key_file)
        self.assertIn("Relay1_csr.pem", cert.tls_csr_file)
        self.assertIn("Relay1_identity_key.pem", cert.identity_key_file)
        self.assertIn("Relay1_identity_pub.pem", cert.identity_pub_key_file)
        self.assertIn("Relay1_onion_key.pem", cert.onion_key_file)
        self.assertIn("Relay1_onion_pub.pem", cert.onion_pub_key_file)

        mock_generate_ssl_cert.assert_called_once_with(
            cert.tls_cert_file, cert.tls_key_file, cert.tls_csr_file, cert.CA_cert_file, cert.CA_key_file, cert.name, "127.0.0.1"
        )

        expected_calls = [
            (cert.identity_key_file, cert.identity_pub_key_file),
            (cert.onion_key_file, cert.onion_pub_key_file),
        ]
        actual_calls = mock_generate_rsa_key_pair.call_args_list
        self.assertEqual(len(actual_calls), 2)
        for call_args, expected in zip(actual_calls, expected_calls):
            self.assertEqual(call_args[0], expected)

        # Ensure SSL context creation was mocked
        self.assertEqual(mock_ssl_context.call_count, 2)  # One for server, one for client

        # Verify load_cert_chain was called on the sontexts
        mock_server_context.load_cert_chain.assert_called_once_with(cert.tls_cert_file, cert.tls_key_file)
        mock_client_context.load_cert_chain.assert_called_once_with(cert.tls_cert_file, cert.tls_key_file)


        # Verify CA certificate loading on contexts
        mock_server_context.load_verify_locations.assert_called_once_with(cert.CA_cert_file)
        mock_client_context.load_verify_locations.assert_called_once_with(cert.CA_cert_file)

    @patch("src.utils.certificates.subprocess.run")
    @patch("src.utils.certificates.tempfile.NamedTemporaryFile")
    def test_generate_ssl_cert_command(self, mock_tempfile, mock_subprocess):
        # Set up the mock for NamedTemporaryFile
        mock_tempfile_instance = mock_tempfile.return_value.__enter__.return_value
        mock_tempfile_instance.name = "/tmp/test_san_config"

        # Get the OpenSSL path
        openssl_path = shutil.which("openssl")

        # Call the function being tested
        generate_ssl_cert("test_cert.pem", "test_key.pem", "test_csr.pem", "ca_cert.pem", "ca_key.pem", "TestCN",
                          "127.0.0.1")

        # Check subprocess command for generating CSR and key
        mock_subprocess.assert_any_call(
            [
                openssl_path, "req", "-newkey", "rsa:2048", "-nodes",
                "-keyout", "test_key.pem", "-out", "test_csr.pem",
                "-subj", "/CN=TestCN",
                "-addext", "subjectAltName=IP:127.0.0.1"
            ],
            check=True,
            shell=False
        )

        # Check subprocess command for signing with CA (with SAN config file)
        mock_subprocess.assert_any_call(
            [
                openssl_path, "x509", "-req", "-in", "test_csr.pem",
                "-CA", "ca_cert.pem", "-CAkey", "ca_key.pem",
                "-CAcreateserial", "-out", "test_cert.pem",
                "-days", "365", "-sha256",
                "-extfile", "/tmp/test_san_config",
                "-extensions", "v3_ca"
            ],
            check=True,
            shell=False
        )

        # Verify that the NamedTemporaryFile was called with delete=False
        mock_tempfile.assert_called_once_with(delete=False)


    def test_generate_ssl_cert(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        ca_cert_file = os.path.join(base_dir, "../certs/ca_cert.pem")
        ca_key_file = os.path.join(base_dir, "../certs/ca_key.key")

        cert_file = "test_cert.pem"
        key_file = "test_key.pem"
        csr_file = "test_csr.pem"

        # Call the actual function
        generate_ssl_cert(cert_file, key_file, csr_file, ca_cert_file, ca_key_file, "TestCN", "127.0.0.1")

        # Verify files are created
        self.assertTrue(os.path.exists(cert_file), "Certificate file was not created.")
        self.assertTrue(os.path.exists(key_file), "Key file was not created.")
        self.assertTrue(os.path.exists(csr_file), "CSR file was not created.")

        # Validate the certificate using OpenSSL
        try:
            openssl_path = shutil.which("openssl")
            result = subprocess.run(
                [openssl_path, "x509", "-in", cert_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            self.assertIn("BEGIN CERTIFICATE", result.stdout.decode(), "Invalid certificate content.")
        except subprocess.CalledProcessError as e:
            self.fail(f"Certificate validation failed: {e.stderr.decode()}")

    @patch("src.utils.certificates.subprocess.run")
    def test_generate_rsa_key_pair_command(self, mock_subprocess):
        generate_rsa_key_pair("test_private.pem", "test_public.pem")

        # Check subprocess commands for private and public key generation
        mock_subprocess.assert_any_call(
            ["openssl", "genrsa", "-out", "test_private.pem", "2048"], check=True
        )
        mock_subprocess.assert_any_call(
            ["openssl", "rsa", "-in", "test_private.pem", "-pubout", "-out", "test_public.pem"], check=True
        )
        self.assertEqual(mock_subprocess.call_count, 2)

    def test_generate_rsa_key_pair(self):
        private_key_path = "test_private.pem"
        public_key_path = "test_public.pem"

        # Call the function under test
        generate_rsa_key_pair(private_key_path, public_key_path)

        # Check if the files are created
        self.assertTrue(os.path.exists(private_key_path), "Private key file was not created.")
        self.assertTrue(os.path.exists(public_key_path), "Public key file was not created.")

        # Validate the private key using OpenSSL
        try:
            result = subprocess.run(
                ["openssl", "rsa", "-check", "-in", private_key_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            self.assertIn("RSA key ok", result.stdout.decode(), "Private key validation failed.")
        except subprocess.CalledProcessError as e:
            self.fail(f"Private key validation failed: {e.stderr.decode()}")

        # Validate the public key using OpenSSL
        try:
            result = subprocess.run(
                ["openssl", "rsa", "-in", private_key_path, "-pubout"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            self.assertIn("BEGIN PUBLIC KEY", result.stdout.decode(), "Public key validation failed.")
        except subprocess.CalledProcessError as e:
            self.fail(f"Public key validation failed: {e.stderr.decode()}")

    def tearDown(self):
        # Remove generated files after each test
        files_to_remove = [
            "test_cert.pem", "test_key.pem", "test_csr.pem", "test_private.pem", "test_public.pem"
        ]
        for file in files_to_remove:
            if os.path.exists(file):
                os.remove(file)


if __name__ == "__main__":
    unittest.main()
