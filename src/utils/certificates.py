import os
import shutil
import subprocess
import sys
import ssl
import tempfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Certificates:
    def __init__(self, name: str, ip: str):
        self.name = name
        self.ip = ip
        self.CA_cert_file = os.path.join(BASE_DIR, '../../certs/ca_cert.pem')
        self.CA_key_file = os.path.join(BASE_DIR, '../../certs/ca_key.key')
        self.tls_cert_file = os.path.join(BASE_DIR, '../../certs/tls/{}_cert.pem'.format(name))
        self.tls_key_file = os.path.join(BASE_DIR, '../../certs/tls/{}_key.pem'.format(name))
        self.tls_csr_file = os.path.join(BASE_DIR, '../../certs/tls/{}_csr.pem'.format(name))
        self.identity_key_file = os.path.join(BASE_DIR, '../../certs/identity/{}_identity_key.pem'.format(name))
        self.identity_pub_key_file = os.path.join(BASE_DIR, '../../certs/identity/{}_identity_pub.pem'.format(name))
        self.onion_key_file = os.path.join(BASE_DIR, '../../certs/onion/{}_onion_key.pem'.format(name))
        self.onion_pub_key_file = os.path.join(BASE_DIR, '../../certs/onion/{}_onion_pub.pem'.format(name))
        self.server_context, self.client_context = None, None
        self.update_tls_certs(self.ip)
        self.update_identity_key()
        self.update_onion_key()

    def get_onion_key(self):
        with open(self.onion_pub_key_file, 'rb') as f:
            return f.read()

    def get_identity_key(self):
        with open(self.identity_pub_key_file, 'rb') as f:
            return f.read()

    def sign(self, message: bytes) -> bytes:
        with open(self.identity_key_file, "rb") as key_file:
            private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature



    def update_onion_key(self):
        """
        For period regeneration
        """
        generate_rsa_key_pair(self.onion_key_file, self.onion_pub_key_file)

    def update_identity_key(self):
        """
        For long term regeneration or security reasons
        """
        generate_rsa_key_pair(self.identity_key_file, self.identity_pub_key_file)

    def update_tls_certs(self, ip):
        """
        For long term regeneration, changing ip, or security reasons
        """
        generate_ssl_cert(self.tls_cert_file, self.tls_key_file, self.tls_csr_file, self.CA_cert_file, self.CA_key_file, self.name, ip)
        self.server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.server_context.load_verify_locations(self.CA_cert_file)
        self.server_context.load_cert_chain(self.tls_cert_file, self.tls_key_file)
        self.server_context.verify_mode = ssl.CERT_REQUIRED
        self.client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.client_context.load_verify_locations(self.CA_cert_file)
        self.client_context.load_cert_chain(self.tls_cert_file, self.tls_key_file)
        self.ip = ip


def generate_ssl_cert(
    cert_file: str,
    key_file: str,
    csr_file: str,
    ca_cert_file: str,
    ca_key_file: str,
    cn: str,
    ip: str,
):
    # print(f"Generating certificate request (CSR) for relay {cn} at {ip} ...")
    openssl_path = check_openssl()

    # Step 1: Generate Certificate Signing Request (CSR) and Key
    cmd = [
        openssl_path,
        "req",
        "-newkey", "rsa:2048",
        "-nodes",
        "-keyout", key_file,
        "-out", csr_file,
        "-subj", f"/CN={cn}",
        "-addext", f"subjectAltName=IP:{ip}",
    ]

    # print("Running command to generate CSR and key:")
    # print(" ".join(cmd))

    try:
        subprocess.run(cmd, check=True, shell=False)
        # print(f"Successfully generated CSR '{csr_file}' and key '{key_file}'.")
    except subprocess.CalledProcessError as e:
        # print("An error occurred while generating the CSR:")
        # print(e)
        sys.exit(1)

    # Step 2: Create a temporary configuration file with SAN
    with tempfile.NamedTemporaryFile(delete=False) as san_config_file:
        san_config_file.write(f"""
[ v3_ca ]
subjectAltName = IP:{ip}
""".encode('iso-8859-1'))
        san_config_file.flush()

        # Step 3: Sign the CSR using the CA and the temporary config file
        # print(f"Signing certificate using custom CA for relay {cn} at {ip} ...")
        cmd = [
            openssl_path,
            "x509",
            "-req",
            "-in", csr_file,
            "-CA", ca_cert_file,
            "-CAkey", ca_key_file,
            "-CAcreateserial",
            "-out", cert_file,
            "-days", "365",
            "-sha256",
            "-extfile", san_config_file.name,
            "-extensions", "v3_ca"
        ]

        # print("Running command to sign the CSR:")
        # print(" ".join(cmd))

        try:
            subprocess.run(cmd, check=True, shell=False)
            # print(f"Successfully signed certificate '{cert_file}' using CA.")
        except subprocess.CalledProcessError as e:
            # print("An error occurred while signing the certificate:")
            # print(e)
            sys.exit(1)
        finally:
            if san_config_file and os.path.exists(san_config_file.name):
                os.remove(san_config_file.name)


def generate_rsa_key_pair(private_key_path: str, public_key_path: str):
    cmd_gen_private_key = [
        "openssl", "genrsa", "-out", private_key_path, "2048"
    ]
    cmd_gen_public_key = [
        "openssl", "rsa", "-in", private_key_path, "-pubout", "-out", public_key_path
    ]
    subprocess.run(cmd_gen_private_key, check=True)
    # print(f"Private key generated")
    subprocess.run(cmd_gen_public_key, check=True)
    # print(f"Public key generated at {public_key_path}")


def check_openssl() -> str:
    openssl_path = shutil.which("openssl")
    if openssl_path is None:
        # print("Error: OpenSSL is not installed or not found in your PATH.")
        sys.exit(1)
    return openssl_path


