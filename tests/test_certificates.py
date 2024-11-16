import unittest
import shutil
import subprocess
import os
from src.utils.certificates import Certificates

class TestCertificates(unittest.TestCase):
    def setUp(self):
        # Create the Certificates class instance
        self.cert = Certificates("Relay1", "127.0.0.1")

    def test_certificates(self):
        # Assertions: Check that all files are created
        self.assertTrue(os.path.exists(self.cert.tls_cert_file), "TLS certificate file not created.")
        self.assertTrue(os.path.exists(self.cert.tls_key_file), "TLS key file not created.")
        self.assertTrue(os.path.exists(self.cert.identity_key_file), "Identity private key not created.")
        self.assertTrue(os.path.exists(self.cert.identity_pub_key_file), "Identity public key not created.")
        self.assertTrue(os.path.exists(self.cert.onion_key_file), "Onion private key not created.")
        self.assertTrue(os.path.exists(self.cert.onion_pub_key_file), "Onion public key not created.")

        # Validate TLS certificate
        self._validate_tls_certificate(self.cert.tls_cert_file)

        # Validate Identity Keys
        self._validate_rsa_keys(self.cert.identity_key_file, self.cert.identity_pub_key_file)

        # Validate Onion Keys
        self._validate_rsa_keys(self.cert.onion_key_file, self.cert.onion_pub_key_file)

        # Validate SSL Context
        self.assertIsNotNone(self.cert.server_context, "Server SSL context not created.")
        self.assertIsNotNone(self.cert.client_context, "Client SSL context not created.")

        # Ensure the server context can load the cert chain
        try:
            self.cert.server_context.load_cert_chain(self.cert.tls_cert_file, self.cert.tls_key_file)
        except Exception as e:
            self.fail(f"Server SSL context failed to load certificate chain: {e}")

        # Ensure the client context can verify the CA certificate
        try:
            self.cert.client_context.load_verify_locations(cafile=self.cert.tls_cert_file)
        except Exception as e:
            self.fail(f"Client SSL context failed to load CA certificate: {e}")

    def tearDown(self):
        # Clean up all generated certificate and key files
        for file_path in [
            self.cert.tls_cert_file, self.cert.tls_key_file, self.cert.tls_csr_file,
            self.cert.identity_key_file, self.cert.identity_pub_key_file,
            self.cert.onion_key_file, self.cert.onion_pub_key_file
        ]:
            if os.path.exists(file_path):
                os.remove(file_path)

    def _validate_tls_certificate(self, cert_file):
        # Validate the TLS certificate using OpenSSL
        openssl_path = shutil.which("openssl")
        result = subprocess.run(
            [openssl_path, "x509", "-in", cert_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        self.assertIn("BEGIN CERTIFICATE", result.stdout.decode(), "TLS certificate content is invalid.")

    def _validate_rsa_keys(self, private_key_file, public_key_file):
        # Validate the private key
        result = subprocess.run(
            ["openssl", "rsa", "-check", "-in", private_key_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        self.assertIn("RSA key ok", result.stdout.decode(), "Private RSA key validation failed.")

        # Validate the public key
        result = subprocess.run(
            ["openssl", "rsa", "-in", private_key_file, "-pubout"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        self.assertIn("BEGIN PUBLIC KEY", result.stdout.decode(), "Public RSA key validation failed.")

if __name__ == "__main__":
    unittest.main()