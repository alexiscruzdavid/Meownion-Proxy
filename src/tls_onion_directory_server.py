import json
import ssl
import logging
from pathlib import Path
from flask import Flask, request, jsonify
from onion_directory import OnionDirectory
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('directory.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('DirectoryServer')

def generate_certificates(cert_path: Path, logger):
    """Generate self-signed certificates for development/testing"""
    logger.info("Generating new self-signed certificates...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Directory Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "directory.local"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    with open(cert_path / 'key.pem', "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(cert_path / 'cert.pem', "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    logger.info(f"Certificates generated in {cert_path}")

def create_app(cert_path: Path = Path('certs')):
    app = Flask(__name__)
    logger = setup_logging()
    
    cert_path.mkdir(exist_ok=True)
    
    if not (cert_path / 'cert.pem').exists() or not (cert_path / 'key.pem').exists():
        generate_certificates(cert_path, logger)
    
    directory = OnionDirectory()
    
    @app.before_request
    def verify_secure_connection():
        if not request.is_secure and app.env == 'production':
            return jsonify({"error": "HTTPS required"}), 403

    @app.route('/upload_state', methods=['POST'])
    def upload_state():
        data = request.json
        if not all(k in data for k in ['ip', 'port', 'onion_key', 'long_term_key', 'signature']):
            return jsonify({"error": "Missing required fields"}), 400
        
        success = directory.update_relay_state(
            data['ip'],
            data['port'],
            data['onion_key'],
            data['long_term_key'],
            bytes.fromhex(data['signature'])
        )
        
        if success:
            return jsonify({"status": "success"}), 200
        return jsonify({"error": "Invalid signature"}), 401

    @app.route('/heartbeat', methods=['POST'])
    def heartbeat():
        data = request.json
        if not all(k in data for k in ['ip', 'port', 'signature']):
            return jsonify({"error": "Missing required fields"}), 400
        
        success = directory.update_heartbeat(
            data['ip'],
            data['port'],
            bytes.fromhex(data['signature'])
        )
        
        if success:
            return jsonify({"status": "success"}), 200
        return jsonify({"error": "Invalid relay or signature"}), 401

    @app.route('/download_states', methods=['GET'])
    def download_states():
        return jsonify(directory.get_relay_states())
        
    return app

if __name__ == '__main__':
    cert_path = Path('../certs/tls')
    app = create_app(cert_path)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=str(cert_path / 'cert.pem'),
        keyfile=str(cert_path / 'key.pem')
    )
    
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256')
    
    app.run(
        host="127.0.0.1",
        port=8001,
        ssl_context=context,
        debug=False
    )