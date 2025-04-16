import oqs
import base64

# Choose Kyber768 KEM algorithm
kem_name = "Kyber512"
print(f"Generating PQC key pair for: {kem_name}")

try:
    # Using the OQS KeyEncapsulation class
    # Make sure the class name is spelled correctly: KeyEncapsulation
    with oqs.KeyEncapsulation(kem_name) as kem:
        # Generate public and private keys
        public_key = kem.generate_keypair()
        # Note: export_secret_key() returns the private key bytes
        # In some versions/wrappers, you might need to store it earlier
        # but this is the pattern from your original file.
        private_key = kem.export_secret_key()

        # Encode keys in Base64 for easier copy/paste
        public_key_b64 = base64.b64encode(public_key).decode('utf-8')
        private_key_b64 = base64.b64encode(private_key).decode('utf-8')

        print("\n--- RECEIVER PQC KEYS (SAVE THESE) ---")
        print(f"Algorithm: {kem_name}")
        # Optional: Add key length prints if desired, using kem.details
        # print(f"Public Key Length (bytes): {kem.details['length_public_key']}")
        # print(f"Secret Key Length (bytes): {kem.details['length_secret_key']}")
        print(f"Public Key (Base64):\n{public_key_b64}")
        print(f"\nPrivate Key (Base64):\n{private_key_b64}")
        print("--- END RECEIVER PQC KEYS ---")

        # Verification check (optional)
        # The API from your original file used encapsulate_secret/decapsulate_secret
        # Ensure these methods exist in the version provided by pqcow-liboqs.
        # If they don't, the API might differ slightly (e.g., separate encapsulate/decapsulate calls)
        # --- Start of Verification check section ---
        print("\n[*] Performing verification check...")

        # Use kem.encaps() - it likely takes the public key
        ciphertext, shared_secret_sender = kem.encap_secret(public_key)

        # Use kem.decaps() - it likely takes the ciphertext first, then the private key
        shared_secret_receiver = kem.decap_secret(ciphertext)

        assert shared_secret_sender == shared_secret_receiver

        # Optional: Use kem.details dictionary for lengths if needed and available
        try:
            print(f"[+] Shared Secret Length (bytes): {kem.details['length_shared_secret']}")
            print(f"[+] Ciphertext Length (bytes): {kem.details['length_ciphertext']}")
        except (AttributeError, KeyError):
            print("[!] Could not retrieve lengths from kem.details.")  # Handle cases where details aren't available

        print("[INFO] Key pair generation and KEM verification successful.")
        # --- End of Verification check section ---

except AttributeError as e:
    # This might happen if KeyEncapsulation class or its methods aren't found
    print(f"[!] AttributeError: {e}")
    print(f"[!] Ensure the 'pqcow-liboqs' library is installed correctly and provides the expected 'oqs' API.")
except oqs.MechanismNotSupportedError as e:  # Catch specific OQS error
    print(f"[!] MechanismNotSupportedError: {e}")
    print(f"[!] The algorithm '{kem_name}' is not supported/enabled in this liboqs build.")
except Exception as e:
    print(f"[!] An unexpected error occurred during verification: {e}")
    import traceback

    traceback.print_exc()  # Print full traceback for unexpected errors