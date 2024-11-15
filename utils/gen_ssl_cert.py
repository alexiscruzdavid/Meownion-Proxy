import shutil
import subprocess
import sys

import fire


def check_openssl() -> str:
    openssl_path = shutil.which("openssl")
    if openssl_path is None:
        print("Error: OpenSSL is not installed or not found in your PATH.")
        sys.exit(1)
    return openssl_path


def generate_self_signed_cert(
    cert_file: str = "certs/cdn_cert.pem",
    key_file: str = "certs/cdn_key.pem",
    origin_domain: str = "",
):
    print(f"Generating self-signed certificate for {origin_domain} ...")
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
        "-subj", f"/CN={origin_domain}",
        "-addext", f"subjectAltName=DNS:{origin_domain}",
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


if __name__ == "__main__":
    fire.Fire(generate_self_signed_cert)
