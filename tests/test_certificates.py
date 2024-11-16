import unittest
from unittest.mock import patch, MagicMock
from src.utils.certificates import Certificates, generate_ssl_cert, generate_rsa_key_pair, check_openssl
import os


class TestCertificates(unittest.TestCase):
    @patch("src.utils.certificates.generate_ssl_cert")
    @patch("src.utils.certificates.generate_rsa_key_pair")
    @patch("os.path.join")
    def test_initialization(self, mock_path_join, mock_generate_rsa_key_pair, mock_generate_ssl_cert):
        mock_path_join.side_effect = lambda *args: "/".join(args)

        cert = Certificates("Relay1", "127.0.0.1")

        # Test attribute assignments
        self.assertEqual(cert.name, "Relay1")
        self.assertIn("Relay1_cert.pem", cert.tls_cert_file)
        self.assertIn("Relay1_key.pem", cert.tls_key_file)
        self.assertIn("Relay1_identity_key.pem", cert.identity_key_file)
        self.assertIn("Relay1_identity_pub.pem", cert.identity_pub_key_file)

        # Ensure helper methods are called
        mock_generate_ssl_cert.assert_called_once_with(
            cert.tls_cert_file, cert.tls_key_file, "Relay1", "127.0.0.1"
        )
        self.assertEqual(mock_generate_rsa_key_pair.call_count, 2)

    @patch("src.utils.certificates.subprocess.run")
    def test_generate_ssl_cert(self, mock_subprocess):
        generate_ssl_cert("test_cert.pem", "test_key.pem", "TestCN", "127.0.0.1")

        # Check subprocess command
        mock_subprocess.assert_called_once_with(
            [
                "openssl", "req", "-newkey", "rsa:2048", "-nodes",
                "-keyout", "test_key.pem", "-x509", "-days", "365",
                "-out", "test_cert.pem", "-subj", "/CN=TestCN",
                "-addext", "subjectAltName=IP:127.0.0.1"
            ],
            check=True,
            shell=False
        )

    @patch("src.utils.certificates.subprocess.run")
    def test_generate_rsa_key_pair(self, mock_subprocess):
        generate_rsa_key_pair("test_private.pem", "test_public.pem")

        # Check subprocess commands for private and public key generation
        mock_subprocess.assert_any_call(
            ["openssl", "genrsa", "-out", "test_private.pem", "2048"], check=True
        )
        mock_subprocess.assert_any_call(
            ["openssl", "rsa", "-in", "test_private.pem", "-pubout", "-out", "test_public.pem"], check=True
        )
        self.assertEqual(mock_subprocess.call_count, 2)

    @patch("src.utils.certificates.shutil.which", return_value=None)
    def test_check_openssl_missing(self, mock_shutil):
        with self.assertRaises(SystemExit):
            check_openssl()

    @patch("src.utils.certificates.shutil.which", return_value="/usr/bin/openssl")
    def test_check_openssl_present(self, mock_shutil):
        self.assertEqual(check_openssl(), "/usr/bin/openssl")

    @patch("ssl.SSLContext.load_cert_chain")
    def test_update_tls_certs(self, mock_load_cert_chain):
        with patch("src.utils.certificates.generate_ssl_cert") as mock_generate_ssl_cert:
            cert = Certificates("Relay1", "127.0.0.1")
            mock_generate_ssl_cert.assert_called_once_with(
                cert.tls_cert_file, cert.tls_key_file, "Relay1", "127.0.0.1"
            )
            mock_load_cert_chain.assert_called_once_with(cert.tls_cert_file, cert.tls_key_file)


if __name__ == "__main__":
    unittest.main()
