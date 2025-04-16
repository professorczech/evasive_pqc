import oqs
import base64

# Choose Kyber768 KEM algorithm
kem_name = "Kyber768"
print(f"Generating PQC key pair for: {kem_name}")

# Using the OQS KeyEncapsulation class
with oqs.KeyEncapsulation(kem_name) as kem:
    # Generate public and private keys
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key() # Get the private key bytes

    # Encode keys in Base64 for easier copy/paste (optional)
    public_key_b64 = base64.b64encode(public_key).decode('utf-8')
    private_key_b64 = base64.b64encode(private_key).decode('utf-8')

    print("\n--- RECEIVER PQC KEYS (SAVE THESE) ---")
    print(f"Algorithm: {kem_name}")
    print(f"Public Key (Base64):\n{public_key_b64}")
    print(f"\nPrivate Key (Base64):\n{private_key_b64}")
    print("--- END RECEIVER PQC KEYS ---")

    # Verification check (optional)
    ciphertext, shared_secret_sender = kem.encapsulate_secret(public_key)
    shared_secret_receiver = kem.decapsulate_secret(ciphertext)
    assert shared_secret_sender == shared_secret_receiver
    print("\n[INFO] Key pair generation and KEM verification successful.")