import oqs
#import KeyEncapsulation # This line assumes the oqspy library is installed

def key_encapsulation_mechanism():
    print("--- Demonstrating FIPS 203: Module-Lattice-Based KEM (CRYSTALS-Kyber) ---")

    kem_alg = "Kyber1024" # Chosen from OQS supported algorithms

    try:
        # Step 1: Receiver generates KEM keys
        receiver_kem = oqs.KeyEncapsulation(kem_alg)
        receiver_public_key = receiver_kem.generate_keypair()

        # Step 2: Sender uses Receiver's public key to Encapsulation
        sender_ciphertext, sender_shared_secret = receiver_kem.encap_secret(receiver_public_key)

        # Step 3: Sender sends the ciphertext to Receiver and Receiver uses his private key to Decapsulation
        receiver_shared_secret = receiver_kem.decap_secret(sender_ciphertext)

        # Verify that both shared secrets are identical        
        if receiver_shared_secret == sender_shared_secret:
            print("[SUCCESS] Shared secrets match! Secure key established.")
            print(f" Sender's Shared Secret  (first 16 bytes): {sender_shared_secret[:16].hex()}")
            print(f" Receiver's Shared Secret (first 16 bytes): {receiver_shared_secret[:16].hex()}")
        else:
            print("[FAILURE] Shared secrets do NOT match!")

    except ValueError as e:
        print(f"Error: Could not initialize KEM algorithm '{kem_alg}'. It might not be available or supported. {e}")
        print("Please ensure your oqspy installation supports the chosen algorithm.")
    except Exception as e:
        print(f"An unexpected error occurred during KEM demonstration: {e}")

def digital_signature():
    print("\n--- Demonstrating FIPS 204: Module-Lattice-Based Digital Signature (CRYSTALS-Dilithium) ---")

    sig_alg = "Dilithium5"
    message = b"This is the confidential voting data from the national election."

    try:
        # Step 1: Signer generates a public to verify the signature and a private key to sign the message
        signer_signer = oqs.Signature(sig_alg)
        signer_public_key = signer_signer.generate_keypair()

        # Sterp 2: Signer create a digital signature for the message using his private key
        signature = signer_signer.sign(message)

        # Step 3: Verifier uses the Signer's public key to verify the signature
        responder_verifier = oqs.Signature(sig_alg)
        is_valid = responder_verifier.verify(message, signature, signer_public_key)

        if is_valid:
            print("[SUCCESS] Signature is valid! Message integrity and authenticity confirmed.")
        else:
            print("[FAILURE] Signature is NOT valid!")

    except ValueError as e:
        print(f"Error: Could not initialize Signature algorithm '{sig_alg}'. It might not be available or supported. {e}")
        print("Please ensure your oqspy installation supports the chosen algorithm.")
    except Exception as e:
        print(f"An unexpected error occurred during Digital Signature demonstration: {e}")

def hash_based_signature():
    print("\n--- Demonstrating FIPS 205: Stateless Hash-Based Digital Signature (SPHINCS+) ---")

    sphincs_alg = "SPHINCS+-SHA2-128f-simple"
    message = b"This is the official statement regarding the new government policy."

    try:
        # Step 1: Generating SPHINCS+ key pair for the initiator
        initiator_signer = oqs.Signature(sphincs_alg)
        initiator_public_key = initiator_signer.generate_keypair()
        
        # Step 2: Initiator signs the message using his private key
        signature = initiator_signer.sign(message)

        # Step 3: Responder verifies the signature using the initiator's public key
        responder_verifier = oqs.Signature(sphincs_alg)
        is_valid = responder_verifier.verify(message, signature, initiator_public_key)

        if is_valid:
            print("[SUCCESS] SPHINCS+ signature is valid! Message integrity and authenticity confirmed.")
        else:
            print("[FAILURE] SPHINCS+ signature is NOT valid!")

    except ValueError as e:
        print(f"Error: Could not initialize SPHINCS+ algorithm '{sphincs_alg}'. It might not be available or supported. {e}")
        print("Please ensure your oqspy installation supports the chosen algorithm.")
    except Exception as e:
        print(f"An unexpected error occurred during SPHINCS+ demonstration: {e}") 

if __name__ == "__main__":
    key_encapsulation_mechanism()
    digital_signature()
    hash_based_signature()