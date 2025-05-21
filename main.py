import sys
import oqs


def demonstrate_ml_kem():
    """Demonstrate FIPS 203: ML-KEM for key encapsulation."""
    print("=== FIPS 203: ML-KEM Demonstration ===")
    kemalg = "ML-KEM-768"  # NIST-standardized algorithm
    try:
        kem = oqs.KeyEncapsulation(kemalg)
        
        # Generate key pair
        public_key = kem.generate_keypair()
        
        # Encapsulation (e.g., by recipient)
        ciphertext, shared_secret_server = kem.encap_secret(public_key)
        print(f"ML-KEM-768 encapsulation complete. Ciphertext size: {len(ciphertext)} bytes")
        
        # Decapsulation (e.g., by sender)
        shared_secret_client = kem.decap_secret(ciphertext)
        print("ML-KEM-768 decapsulation complete. Decapsulation is:", shared_secret_client)
        
        # Verify shared secret
        assert shared_secret_server == shared_secret_client, "Shared secrets do not match!"
        print("ML-KEM-768 shared secret established successfully.")
        return shared_secret_client
    except AttributeError as e:
        print(f"Error in ML-KEM: {e}. Ensure 'oqs' library is updated and supports ML-KEM-768.")
        return None
    except Exception as e:
        print(f"Unexpected error in ML-KEM: {e}")
        return None

def demonstrate_ml_dsa():
    """Demonstrate FIPS 204: ML-DSA for digital signatures."""
    print("\n=== FIPS 204: ML-DSA Demonstration ===")
    sigalg = "ML-DSA-65"  # NIST-standardized algorithm
    try:
        signer = oqs.Signature(sigalg)
        
        # Generate key pair
        public_key = signer.generate_keypair()
        print("ML-DSA-65 key pair generated.")
        
        # Sign a message
        message = b"Secure voting system message"
        signature = signer.sign(message)
        print(f"ML-DSA-65 signature created. Signature size: {len(signature)} bytes")
        
        # Verify signature
        verifier = oqs.Signature(sigalg)
        is_valid = verifier.verify(message, signature, public_key)
        print("ML-DSA-65 signature verification:", "Valid" if is_valid else "Invalid")
        return is_valid
    except AttributeError as e:
        print(f"Error in ML-DSA: {e}. Ensure 'oqs' library is updated and supports ML-DSA-65.")
        return False
    except Exception as e:
        print(f"Unexpected error in ML-DSA: {e}")
        return False

def demonstrate_slh_dsa():
    """Demonstrate FIPS 205: SLH-DSA for digital signatures."""
    print("\n=== FIPS 205: SLH-DSA Demonstration ===")
    sigalg = "SLH-DSA-SHA2-192s"  # NIST-standardized algorithm
    try:
        signer = oqs.Signature(sigalg)
        
        # Generate key pair
        public_key = signer.generate_keypair()
        print("SLH-DSA-SHA2-192s key pair generated.")
        
        # Sign a message
        message = b"Secure voting system message"
        signature = signer.sign(message)
        print(f"SLH-DSA-SHA2-192s signature created. Signature size: {len(signature)} bytes")
        
        # Verify signature
        verifier = oqs.Signature(sigalg)
        is_valid = verifier.verify(message, signature, public_key)
        print("SLH-DSA-SHA2-192s signature verification:", "Valid" if is_valid else "Invalid")
        return is_valid
    except AttributeError as e:
        print(f"Error in SLH-DSA: {e}. Ensure 'oqs' library is updated and supports SLH-DSA-SHA2-192s.")
        return False
    except Exception as e:
        print(f"Unexpected error in SLH-DSA: {e}")
        return False

def main():
    """Run demonstrations for FIPS 203, 204, and 205."""
    print(f"Running PQC demo at {datetime.datetime.now(datetime.timezone.utc)}")
    
    # Check oqs version
    try:
        print(f"Using oqs-python version: {oqs.__version__}")
    except AttributeError:
        print("Warning: Could not retrieve oqs-python version.")
    
    # Demonstrate ML-KEM (FIPS 203)
    shared_secret = demonstrate_ml_kem()
    
    # Demonstrate ML-DSA (FIPS 204)
    ml_dsa_valid = demonstrate_ml_dsa()
    
    # Demonstrate SLH-DSA (FIPS 205)
    slh_dsa_valid = demonstrate_slh_dsa()
    
    # Summary
    print("\n=== Summary ===")
    if shared_secret:
        print("FIPS 203 (ML-KEM-768): Shared secret established.")
    else:
        print("FIPS 203 (ML-KEM-768): Failed to establish shared secret.")
    print("FIPS 204 (ML-DSA-65): Signature", "valid" if ml_dsa_valid else "invalid")
    print("FIPS 205 (SLH-DSA-SHA2-192s): Signature", "valid" if slh_dsa_valid else "invalid")

if __name__ == "__main__":
    import datetime
    main()