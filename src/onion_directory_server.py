import json
from flask import Flask, request, jsonify
from onion_directory import OnionDirectory

app = Flask(__name__)
directory = OnionDirectory()

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

if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8001)