import ecdsa
import hashlib
import base58
import time
import requests
import secrets
from flask import Flask
from keep_alive import keep_alive
import threading

keep_alive()

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1313595983678017649/Bm06HRH4NMy16rBC8Qzae3Uk_tBdRwBlvHPXGZM2gqJWVPEpM4tqINfjjLMZeDZKK_f2'

def send_to_discord(content):
    data = {"content": content}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error sending message to Discord: {e}")

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x02' + vk.to_string()[:32] if vk.to_string()[32] % 2 == 0 else b'\x03' + vk.to_string()[:32]

def public_key_to_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    prepend_network_byte = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(prepend_network_byte).digest()).digest()[:4]
    address = base58.b58encode(prepend_network_byte + checksum)
    return address.decode()

def search_for_private_key(start, end, target_address):
    print(f"Thread started searching from {start:x} to {end:x}")

    while True:
        private_key = secrets.randbelow(end - start) + start  
        private_key_hex = f"{private_key:064x}"
        public_key = private_key_to_public_key(private_key)
        wallet_address = public_key_to_address(public_key)

        if wallet_address == target_address:
            found_message = (
                f"@everyone Found matching private key for target address: {private_key_hex}\n"
                f"Public Key: {public_key.hex()}\n"
                f"Bitcoin Address: {wallet_address}"
            )
            send_to_discord(found_message)
            break

def main():
    target_address = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"
    
    print(f"Starting random private key search for target address")
    send_to_discord(f"Starting random private key search for target address")

    start_time = time.time()

    start = int("40000000000000000", 16)
    end = int("7ffffffffffffffff", 16)

    num_threads = 4
    thread_range = (end - start) // num_threads

    threads = []
    for i in range(num_threads):
        thread_start = start + i * thread_range
        thread_end = start + (i + 1) * thread_range if i < num_threads - 1 else end
        thread = threading.Thread(target=search_for_private_key, args=(thread_start, thread_end, target_address))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print(f"Total search time: {time.time() - start_time} seconds")

if __name__ == "__main__":
    main()
