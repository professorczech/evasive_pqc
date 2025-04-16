# Evasive Payload Delivery (PQC KEM + AES + Marshal + Zlib + TLS Mimicry)

## ☢️☢️☢️ EXTREME DANGER & SECURITY WARNING ☢️☢️☢️

This project demonstrates highly experimental and inherently **DANGEROUS** techniques involving Post-Quantum Cryptography (PQC) for key exchange, payload serialization via `marshal`, and direct code execution via `exec()`. It is intended **SOLELY** for advanced educational purposes within **SECURE, ISOLATED, DISPOSABLE LABORATORY ENVIRONMENTS**.

* **UNMARSHAL IS FUNDAMENTALLY UNSAFE:** The `marshal.loads()` function is **NOT** designed for untrusted data. Maliciously crafted input can **CRASH** the Python interpreter or potentially lead to **ARBITRARY CODE EXECUTION** during deserialization, *before* `exec()`. **DO NOT USE `marshal` WITH UNTRUSTED DATA OUTSIDE A LAB.**
* **EXEC() IS DANGEROUS:** Executing code received dynamically via `exec()` grants full permissions. This is a **CRITICAL VULNERABILITY**.
* **PQC IS EXPERIMENTAL:** While based on NIST PQC standardization candidates (like CRYSTALS-Kyber), PQC libraries and implementations are still evolving. This project uses the **`pqcow-liboqs`** package, which provides pre-compiled binaries for the `liboqs` C library, to simplify setup on some platforms.
* **INSECURE KEYS/CERTS:** PQC keys are hardcoded for the lab. TLS uses self-signed certificates providing NO real trust or validation. This setup is **NOT SECURE** for real-world use.
* **LAB USE ONLY:** **NEVER** run this code on production systems or any machine you cannot afford to completely compromise and wipe.
* **EVASION IS LIMITED/THEORETICAL:** While incorporating PQC, TLS, chunking, etc., adds complexity, it **DOES NOT GUARANTEE EVASION** of modern NGFW/IPS/EDR. Traffic analysis, behavioral detection, and endpoint security still apply. PQC primarily addresses future quantum threats to key exchange, not current conventional detection methods.

## Description

This project enhances previous payload delivery examples by incorporating:

1.  **PQC Key Exchange:** Uses **CRYSTALS-Kyber512** (via the `oqs` module provided by `pqcow-liboqs`) Key Encapsulation Mechanism (KEM) to securely establish a shared symmetric key for AES. (Note: Kyber768 was not enabled in the tested pre-compiled package).
2.  **Hybrid Encryption:** The PQC KEM establishes the key; AES-GCM encrypts the actual payload using that key.
3.  **TLS Wrapping:** Communication occurs over a TLS-encrypted socket (using Python's `ssl` module and self-signed certificates) typically on port 443 to mimic HTTPS traffic at the transport layer.
4.  **Basic HTTP Mimicry:** Sends minimal HTTP POST headers *inside* the TLS tunnel before the payload data.
5.  **Payload Obfuscation:** Retains `marshal` serialization of compiled Python code and `zlib` compression before encryption.
6.  **Network Evasion Tactics:** Retains chunked data transmission with length prefixing and variable timing delays.

The goal is to demonstrate a complex, layered approach combining PQC key exchange, standard TLS encryption, and payload obfuscation/delivery tactics in a controlled lab setting.

## Features

* Post-Quantum Key Exchange (**CRYSTALS-Kyber512 KEM** via `oqs` module from `pqcow-liboqs`)
* Hybrid Encryption (PQC KEM + AES-GCM)
* TLS Wrapped Communication (via `ssl`, mimics HTTPS)
* Basic HTTP Header Mimicry
* Python Code Object Serialization (`marshal`)
* Data Compression (`zlib`)
* Chunked Transmission with Length Prefixing (`struct`)
* Variable Timing Delays (`time`, `random`)
* Sender (`evasive_pqc_sender.py`): Orchestrates payload creation and secure transmission.
* Receiver (`evasive_pqc_receiver.py`): Listens over TLS, reverses the process, **UNSAFELY UNMARSHALS**, and **DANGEROUSLY EXECUTES**.

## Requirements

* **Python 3:** Scripts require Python 3.x.
* **`pqcow-liboqs`:** Provides the `oqs` module with pre-compiled `liboqs` C library binaries (intended to avoid manual compilation).
    ```bash
    pip install pqcow-liboqs
    ```
    *(Note: This is an unofficial package providing pre-compiled binaries. Use at your own risk. If it fails or doesn't include needed algorithms, you may need to build `liboqs` and `liboqs-python` from source).*
* **`pycryptodome`:** For AES-GCM.
    ```bash
    pip install pycryptodome
    ```
* **OpenSSL:** Needed to generate the self-signed TLS certificate/key (usually pre-installed on Linux/macOS, available for Windows).
* **Two Machines:** A sender (Kali) and receiver (Victim1) in an isolated network lab. Root/sudo access may be needed to bind to port 443.

## Setup

1.  **Install Dependencies:** Run `pip install pqcow-liboqs pycryptodome` on both machines.
2.  **Generate PQC Keys:** Run `python generate_keys.py` *once*. This script is now configured for **Kyber512**. Securely copy the **Base64 public key** into `RECEIVER_PQC_PUBLIC_KEY_B64` in the **sender** script. Copy the **Base64 private key** into `RECEIVER_PQC_PRIVATE_KEY_B64` in the **receiver** script. Ensure `PQC_KEM_ALG` is set to `"Kyber512"` in both sender and receiver scripts.
3.  **Generate TLS Cert/Key:** On the **receiver** machine, in the directory where the receiver script will run, execute:
    ```bash
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 365 -nodes -subj "/CN=victim1.lab.local"
    ```
    This creates `server.key` and `server.crt`. Ensure `CERT_FILE` and `KEY_FILE` variables in the receiver script match these filenames.
4.  **Configure IPs/Ports:**
    * Set `TARGET_IP` in the sender script.
    * Ensure `TARGET_PORT` (sender) and `LISTEN_PORT` (receiver) match (default is 443).
    * Ensure `LISTEN_IP` in the receiver is correct (`0.0.0.0` or specific IP).
5.  **Payload:** Modify `payload_code` in the sender if desired (use only harmless commands).

## Usage

1.  **Start the Receiver:** On the receiver machine (Victim1), run (likely needs `sudo` for port 443):
    ```bash
    python3 evasive_pqc_receiver.py
    ```
    It will load TLS certs and listen. *(Note: You might see a `UserWarning` about `liboqs` version mismatch - this can likely be ignored if the script functions correctly).*

2.  **Run the Sender:** On the sender machine (Kali), run:
    ```bash
    python3 evasive_pqc_sender.py
    ```
    It performs PQC KEM (Kyber512), encrypts, connects over TLS, and sends data. *(Note: The `UserWarning` might appear here too).*

3.  **Observe Output:** Monitor console output on both machines. The receiver should (if all keys/certs are correct) decrypt, decompress, unmarshal, and execute the payload. **Watch carefully for errors** at any stage.

## How It Works

1.  **Sender:**
    * Initializes the KEM using `oqs.KeyEncapsulation("Kyber512")`.
    * Uses the receiver's PQC public key and the `kem.encap_secret()` method (specific to this wrapper version) to generate a PQC ciphertext and a shared secret (AES key).
    * Compiles -> Marshals -> Compresses (zlib) the `payload_code`.
    * Encrypts the result using AES-GCM with the derived shared secret (AES key).
    * Establishes a raw TCP connection.
    * Wraps the connection in TLS (client mode, skipping verification for self-signed cert).
    * Sends minimal HTTP POST headers inside the TLS tunnel.
    * Sends the PQC ciphertext (prefixed with length).
    * Sends the AES-encrypted payload (chunked, timed, length-prefixed).

2.  **Receiver:**
    * Sets up a TLS listening socket using the self-signed certificate/key.
    * Accepts a raw connection and wraps it in TLS (server mode).
    * Reads and discards the initial bytes assuming they are HTTP headers (up to `\r\n\r\n`).
    * Receives the PQC ciphertext (reading its length prefix).
    * Initializes the KEM using `oqs.KeyEncapsulation("Kyber512", RECEIVER_PQC_PRIVATE_KEY)`.
    * Uses the `kem.decap_secret(kem_ciphertext)` method (specific to this wrapper version, using the implicitly stored private key) to derive the *same* shared secret (AES key).
    * Receives the AES-encrypted payload (using chunking/timing/length logic).
    * Uses the derived AES key to decrypt the AES payload (verifying integrity via GCM tag).
    * Decompresses the decrypted data (`zlib`).
    * **UNSAFELY** unmarshals the bytes back into a Python code object.
    * **DANGEROUSLY** executes the code object via `exec()`.

## Evasion Considerations & Limitations

* **TLS Layer:** Mimics HTTPS transport, potentially bypassing basic port-based filtering. However, self-signed certificates are inherently suspicious and easily detected. NGFWs performing TLS decryption would negate this layer's confidentiality *if* they have the appropriate CA cert installed (not the case here, but relevant conceptually).
* **PQC KEM:** Makes the key exchange resistant to future quantum attacks (using Kyber512 level here). It *does not* inherently make the C2 traffic less detectable by *current* conventional means (behavioral, traffic volume, endpoint analysis). The PQC handshake/ciphertext *might* present a unique signature if not wrapped in TLS, but here it's hidden within the TLS tunnel.
* **HTTP Mimicry:** Very basic. Sophisticated DPI can easily distinguish this from real browser traffic (missing headers, simplistic structure, fixed content type).
* **Payload Obfuscation:** Marshal+Zlib+AES hides the payload well, but the final execution via `marshal.loads` and `exec` remains the weakest link and a major detection vector on the endpoint (EDR).
* **Network Patterns:** Chunking/timing helps obscure simple signatures but doesn't eliminate the fundamental pattern of a client connecting to a server and transferring data. Low-and-slow techniques can further enhance this but add latency.

This complex example serves to demonstrate layering multiple advanced concepts (PQC, TLS, obfuscation, network tactics) in a **strictly educational, non-production** context, highlighting both the potential and the significant inherent risks and limitations.