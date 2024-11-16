import os
import shutil
import subprocess
import sys
import ssl


class Certificates:
    def __init__(self, name: str, ip: str):
        self.name = name
        self.tls_cert_file = 'certs/tls/{}_cert.pem'.format(name)
        self.tls_key_file = 'certs/tls/{}_key.pem'.format(name)
        self.identity_key_file = 'certs/identity/{}_identity_key.pem'.format(name)
        self.identity_pub_key_file = 'certs/identity/{}_identity_pub.pem'.format(name)
        self.onion_key_file = 'certs/onion/{}_onion_key.pem'.format(name)
        self.onion_pub_key_file = 'certs/onion/{}_onion_pub.pem'.format(name)
        self.server_context, self.client_context = None, None

        self.update_tls_certs(ip)
        self.update_identity_key()
        self.update_onion_key()

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
        generate_ssl_cert(self.tls_cert_file, self.tls_key_file, self.name, ip)
        self.server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.server_context.load_cert_chain(self.tls_cert_file, self.tls_key_file)
        self.server_context.verify_mode = ssl.CERT_REQUIRED
        self.client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)


def generate_ssl_cert(
    cert_file: str,
    key_file: str,
    cn: str,
    ip: str,
):
    print(f"Generating self-signed certificate for relay {cn} at {ip} ...")
    openssl_path = check_openssl()

    # fmt: off
    cmd = [
        openssl_path,
        "req",
        "-newkey", "rsa:2048",
        "-nodes",
        "-keyout", key_file,
        "-x509",
        "-days", "365",
        "-out", cert_file,
        "-subj", f"/CN={cn}",
        "-addext", f"subjectAltName=IP:{ip}",
    ]
    # fmt: on

    print("Running command:")
    print(" ".join(cmd))

    try:
        subprocess.run(cmd, check=True, shell=False)
        print(f"Successfully generated certificate '{cert_file}' and key '{key_file}'.")
    except subprocess.CalledProcessError as e:
        print("An error occurred while generating the certificate:")
        print(e)
        sys.exit(1)

def generate_rsa_key_pair(private_key_path: str, public_key_path: str):
    cmd_gen_private_key = [
        "openssl", "genrsa", "-out", private_key_path, "2048"
    ]
    cmd_gen_public_key = [
        "openssl", "rsa", "-in", private_key_path, "-pubout", "-out", public_key_path
    ]

    subprocess.run(cmd_gen_private_key, check=True)
    print(f"Private key generated")
    subprocess.run(cmd_gen_public_key, check=True)
    print(f"Public key generated at {public_key_path}")


def check_openssl() -> str:
    openssl_path = shutil.which("openssl")
    if openssl_path is None:
        print("Error: OpenSSL is not installed or not found in your PATH.")
        sys.exit(1)
    return openssl_path


